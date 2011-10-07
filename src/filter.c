#include <tcpr/application.h>
#include <tcpr/filter.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <search.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

static int finished;

static const char internal_log_path[] = "/var/tmp/tcpr-internal.pcap";
static const char external_log_path[] = "/var/tmp/tcpr-external.pcap";
static const char other_log_path[] = "/var/tmp/tcpr-other.pcap";

struct connection {
	struct tcpr_connection tcpr;
	uint32_t peer_address;
	uint16_t peer_port;
	uint16_t port;
};

struct packet {
	struct ip ip;
	struct tcphdr tcp;
	uint8_t options[40];
};

static int external_log;
static int internal_log;
static int other_log;
static char *external_host = "127.0.0.2";
static char *internal_host = "127.0.0.3";
static int logging;
static int epoll_fd;
static int netfilter_fd;
static int passthrough;
static int raw_socket;
static size_t capture_size = 65536;
static size_t max_events = 256;
static struct connection *connections;
static struct nfq_handle *netfilter_handle;
static struct nfq_q_handle *queue_handle;
static uint16_t queue_number;
static uint32_t external_address;
static uint32_t internal_address;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Filter the packets sent to a Netfilter QUEUE target "
		"through TCPR,\nenabling an application to recover and "
		"migrate its TCP connections.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -i HOST    "
		"Internally, the application is bound to HOST.\n");
	fprintf(stderr, "  -e HOST    "
		"Externally, the application is bound to HOST.\n");
	fprintf(stderr, "  -q NUMBER  "
		"Filter packets on netfilter queue NUMBER.\n");
	fprintf(stderr, "  -T         "
		"Do not use TCPR; deliver packets unchanged.\n");
	fprintf(stderr, "  -l         Log packet traces.\n");
	fprintf(stderr, "  -?         Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "i:e:q:Tl?")) {
		case 'i':
			internal_host = optarg;
			break;
		case 'e':
			external_host = optarg;
			break;
		case 'q':
			queue_number = (uint16_t)atoi(optarg);
			break;
		case 'T':
			passthrough = 1;
			break;
		case 'l':
			logging = 1;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void handle_signal(int s)
{
	(void)s;
	finished = 1;
}

static void setup_signals(void)
{
	sigset_t blockset;
	struct sigaction sa;

	sigemptyset(&blockset);
	sigaddset(&blockset, SIGINT);
	sigaddset(&blockset, SIGTERM);
	sigprocmask(SIG_BLOCK, &blockset, NULL);

	sa.sa_handler = handle_signal;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void setup_priority(void)
{
	if (setpriority(PRIO_PROCESS, 0, -20) < 0)
		perror("Setting priority");
}

static int is_from_peer(struct ip *ip)
{
	return ip->ip_src.s_addr != internal_address;
}

static uint32_t shorten(uint32_t n)
{
	return (n >> 16) + (n & 0xffff);
}

static uint32_t checksum(uint16_t *data, size_t size)
{
	uint32_t sum;
	for (sum = 0; size > 1; size -= 2)
		sum += *data++;
	if (size)
		sum += (uint16_t)*(uint8_t *)data << 16;
	return sum;
}

static void compute_ip_checksum(struct ip *ip)
{
	uint32_t sum = checksum((uint16_t *)ip, ip->ip_hl * 4);
	ip->ip_sum = ~shorten(shorten(sum));
}

static void compute_tcp_checksum(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t size = ntohs(ip->ip_len) - ip->ip_hl * 4;
	uint32_t sum = checksum((uint16_t *)tcp, size)
	    + shorten(ip->ip_dst.s_addr)
	    + shorten(ip->ip_src.s_addr)
	    + htons(ip->ip_p + size);
	tcp->th_sum = ~shorten(shorten(sum));
}

static void externalize_source(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t sum =
	    shorten(~ip->ip_src.s_addr) + shorten(external_address);
	ip->ip_src.s_addr = external_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void internalize_destination(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t sum =
	    shorten(~ip->ip_dst.s_addr) + shorten(internal_address);
	ip->ip_dst.s_addr = internal_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void drop(int id)
{
	if (nfq_set_verdict(queue_handle, id, NF_DROP, 0, NULL) < 0)
		fputs("Error dropping packet.\n", stderr);
}

static void log_packet(int log, struct ip *ip)
{
	uint32_t size;
	struct timeval tv;
	struct {
		uint32_t ts_sec;
		uint32_t ts_usec;
		uint32_t incl_len;
		uint32_t orig_len;
	} header;

	size = ntohs(ip->ip_len);
	gettimeofday(&tv, NULL);
	header.ts_sec = tv.tv_sec;
	header.ts_usec = tv.tv_usec;
	header.incl_len = size;
	header.orig_len = size;
	if (write(log, &header, sizeof(header)) != sizeof(header))
		perror("Writing to log");
	if (write(log, ip, size) != (ssize_t)size)
		perror("Writing to log");
}

static void deliver(int id, struct ip *ip, struct tcphdr *tcp)
{
	/* FIXME: recompute MD5 signature if necessary */
	if (!tcp->th_sum)
		compute_tcp_checksum(ip, tcp);
	if (nfq_set_verdict
	    (queue_handle, id, NF_ACCEPT, ntohs(ip->ip_len),
	     (unsigned char *)ip) < 0)
		fputs("Error delivering packet.\n", stderr);
}

static void inject(struct ip *ip)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip->ip_dst.s_addr;
	if (sendto
	    (raw_socket, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&addr,
	     sizeof(addr)) < 0)
		perror("Injecting packet");
}

static void make_packet(struct ip *ip, struct tcphdr *tcp, uint32_t src,
			uint32_t dst, uint16_t sport, uint16_t dport)
{
	ip->ip_hl = sizeof(*ip) / 4;
	ip->ip_v = 4;
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(*ip) + tcp->th_off * 4);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = src;
	ip->ip_dst.s_addr = dst;
	tcp->th_sport = sport;
	tcp->th_dport = dport;
	/* FIXME: add MD5 signature if necessary */
	compute_ip_checksum(ip);
	compute_tcp_checksum(ip, tcp);
}

static void reset(struct connection *c)
{
	struct packet packet;
	tcpr_reset(&packet.tcp, c->tcpr.state);
	make_packet(&packet.ip, &packet.tcp, c->peer_address, internal_address, c->peer_port, c->port);
	if (logging)
		log_packet(internal_log, &packet.ip);
	inject(&packet.ip);
}

static void recover(struct connection *c)
{
	struct packet packet;
	int i;

	tcpr_recover(&packet.tcp, c->tcpr.state);
	make_packet(&packet.ip, &packet.tcp, c->peer_address, internal_address, c->peer_port, c->port);
	if (logging)
		log_packet(internal_log, &packet.ip);
	inject(&packet.ip);

	tcpr_update(&packet.tcp, c->tcpr.state);
	make_packet(&packet.ip, &packet.tcp, external_address, c->peer_address, c->port, c->peer_port);
	for (i = 0; i < 4; i++) {
		if (logging)
			log_packet(external_log, &packet.ip);
		inject(&packet.ip);
	}
}

static void update(struct connection *c)
{
	struct packet packet;
	tcpr_update(&packet.tcp, c->tcpr.state);
	make_packet(&packet.ip, &packet.tcp, external_address, c->peer_address, c->port, c->peer_port);
	if (logging)
		log_packet(external_log, &packet.ip);
	inject(&packet.ip);
}

static int compare_connections(const void *a, const void *b)
{
	const struct connection *c = a;
	const struct connection *d = b;

	if (c->peer_address < d->peer_address)
		return -1;
	if (d->peer_address < c->peer_address)
		return 1;
	if (c->peer_port < d->peer_port)
		return -1;
	if (d->peer_port < c->peer_port)
		return 1;
	if (c->port < d->port)
		return -1;
	if (d->port < c->port)
		return 1;
	return 0;
}

static int setup_connection_events(struct connection *c)
{
	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.ptr = c;
	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->tcpr.control_socket,
			 &event);
}

static struct connection *get_connection(struct ip *ip, struct tcphdr *tcp)
{
	struct connection key;
	struct connection *c;
	struct connection **node;
	int flags;

	if (is_from_peer(ip)) {
		key.peer_address = ip->ip_src.s_addr;
		key.peer_port = tcp->th_sport;
		key.port = tcp->th_dport;
	} else {
		key.peer_address = ip->ip_dst.s_addr;
		key.peer_port = tcp->th_dport;
		key.port = tcp->th_sport;
	}

	node = tfind(&key, (void **)&connections, compare_connections);
	if (node)
		return *node;

	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	c->peer_address = key.peer_address;
	c->peer_port = key.peer_port;
	c->port = key.port;

	flags = TCPR_CONNECTION_FILTER;
	if (!(tcp->th_flags & TH_ACK))
		flags |= TCPR_CONNECTION_CREATE;
	if (tcpr_setup_connection(&c->tcpr, c->peer_address, c->peer_port, c->port, flags) <
	    0) {
		free(c);
		return NULL;
	}

	if (setup_connection_events(c) < 0) {
		tcpr_teardown_connection(&c->tcpr);
		free(c);
		return NULL;
	}

	if (!tsearch(c, (void **)&connections, compare_connections)) {
		tcpr_teardown_connection(&c->tcpr);
		free(c);
		return NULL;
	}

	return c;
}

static void teardown_connection(struct connection *c)
{
	tdelete(c, (void **)&connections, compare_connections);
	tcpr_teardown_connection(&c->tcpr);
	tcpr_destroy_connection(c->peer_address, c->peer_port, c->port);
}

static int handle_packet(struct nfq_q_handle *q, struct nfgenmsg *m,
			 struct nfq_data *d, void *a)
{
	size_t tcp_size;
	struct connection *c;
	struct ip *ip;
	struct tcphdr *tcp;
	int id;

	(void)q;
	(void)m;
	(void)a;

	id = ntohl((nfq_get_msg_packet_hdr(d))->packet_id);
	nfq_get_payload(d, (char **)&ip);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ip_hl);
	tcp_size = htons(ip->ip_len) - ip->ip_hl * 4;

	if (passthrough) {
		if (logging)
			log_packet(other_log, ip);
		deliver(id, ip, tcp);
		return 0;
	}

	c = get_connection(ip, tcp);
	if (!c) {
		if (logging)
			log_packet(other_log, ip);
		drop(id);
		return 0;
	}

	if (is_from_peer(ip)) {
		if (logging)
			log_packet(external_log, ip);
		tcpr_filter_peer(c->tcpr.state, tcp, tcp_size);
		internalize_destination(ip, tcp);
		if (logging)
			log_packet(internal_log, ip);
		deliver(id, ip, tcp);
	} else {
		if (logging)
			log_packet(internal_log, ip);
		switch (tcpr_filter(c->tcpr.state, tcp, tcp_size)) {
		case TCPR_DELIVER:
			externalize_source(ip, tcp);
			if (logging)
				log_packet(external_log, ip);
			deliver(id, ip, tcp);
			break;
		case TCPR_DROP:
			drop(id);
			break;
		case TCPR_RESET:
			drop(id);
			reset(c);
			break;
		case TCPR_RECOVER:
			drop(id);
			recover(c);
			break;
		}
	}

	if (c->tcpr.state->done)
		teardown_connection(c);
	return 0;
}

static void setup_netfilter(void)
{
	netfilter_handle = nfq_open();
	if (!netfilter_handle) {
		fputs("Error opening the queue interface.\n", stderr);
		exit(EXIT_FAILURE);
	}

	nfq_unbind_pf(netfilter_handle, AF_INET);
	if (nfq_bind_pf(netfilter_handle, AF_INET) < 0) {
		fputs("Error binding the queue handler.\n", stderr);
		exit(EXIT_FAILURE);
	}

	queue_handle = nfq_create_queue(netfilter_handle, queue_number, handle_packet, NULL);
	if (!queue_handle) {
		fputs("Error creating the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}

	if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, capture_size) < 0) {
		fputs("Error setting up the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}

	netfilter_fd = nfq_fd(netfilter_handle);
}

static void setup_events(void)
{
	struct epoll_event event;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("Error opening epoll");
		exit(EXIT_FAILURE);
	}

	event.events = EPOLLIN;
	event.data.ptr = NULL;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, netfilter_fd, &event) < 0) {
		perror("Error adding to epoll");
		exit(EXIT_FAILURE);
	}
}

static int start_log(const char *path)
{
	int fd;
	struct {
		uint32_t magic_number;
		uint16_t version_major;
		uint16_t version_minor;
		int32_t  thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;
		uint32_t network;
	} header = {0xa1b2c3d4, 2, 4, 0, 0, capture_size, 101};

	fd = open(path, O_WRONLY | O_CREAT, 0664);
	if (fd < 0) {
		perror("Opening log");
		exit(EXIT_FAILURE);
	}
	if (write(fd, &header, sizeof(header)) != sizeof(header)) {
		perror("Writing log header");
		exit(EXIT_FAILURE);
	}
	if (lseek(fd, 0, SEEK_END) < 0) {
		perror("Seeking in log");
		exit(EXIT_FAILURE);
	}
	return fd;
}

static void setup_logging(void)
{
	if (!logging)
		return;
	external_log = start_log(external_log_path);
	internal_log = start_log(internal_log_path);
	other_log = start_log(other_log_path);
}

static void setup_addresses(void)
{
	struct addrinfo *ai;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(internal_host, NULL, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving internal address: %s\n",
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	internal_address =
	    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ai);

	err = getaddrinfo(external_host, NULL, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving internal address: %s\n",
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	external_address =
	    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ai);
}

static void setup_raw_socket(void)
{
	raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_socket < 0) {
		perror("Opening raw socket");
		exit(EXIT_FAILURE);
	}
}

static void handle_event(struct epoll_event *e)
{
	char data[capture_size];
	ssize_t size;

	if (e->data.ptr == NULL) {
		size = read(netfilter_fd, data, sizeof(data));
		if (size < 0)
			perror("Error reading a packet");
		nfq_handle_packet(netfilter_handle, data, size);
	} else {
		struct connection *c = e->data.ptr;
		size = read(c->tcpr.control_socket, data, sizeof(data));
		if (c->tcpr.state->done)
			teardown_connection(c);
		else if (c->tcpr.state->have_fin
					&& !c->tcpr.state->saved.done_writing)
			reset(c);
		else
			update(c);
	}
}

static void handle_events(void)
{
	int i;
	int n;
	sigset_t sigs;
	struct epoll_event events[max_events];

	sigemptyset(&sigs);
	while (!finished) {
		n = epoll_pwait(epoll_fd, events, max_events, -1, &sigs);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("Error waiting for events");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < n; i++)
			handle_event(&events[i]);
	}
}

static void teardown_raw_socket(void)
{
	close(raw_socket);
}

static void teardown_events(void)
{
	close(epoll_fd);
}

static void teardown_netfilter(void)
{
	nfq_destroy_queue(queue_handle);
	nfq_close(netfilter_handle);
}

static void teardown_logging(void)
{
	if (!logging)
		return;
	close(external_log);
	close(internal_log);
	close(other_log);
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);

	setup_signals();
	setup_priority();
	setup_addresses();
	setup_logging();
	setup_netfilter();
	setup_events();
	setup_raw_socket();

	handle_events();

	teardown_raw_socket();
	teardown_events();
	teardown_netfilter();
	teardown_logging();

	return EXIT_SUCCESS;
}
