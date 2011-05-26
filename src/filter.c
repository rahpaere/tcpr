#include <tcpr/filter.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <search.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

static int finished;

static const char state_path_format[] = "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".state";
static const char ctl_path_format[] = "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".ctl";

struct connection {
	struct tcpr *state;
	int ctl_socket;
	struct sockaddr_un ctl_address;
	struct sockaddr_in peer_address;
	uint16_t port;
};

struct filter {
	char *external_host;
	char *internal_host;
	int epoll_fd;
	int netfilter_fd;
	int raw_socket;
	size_t capture_size;
	size_t max_events;
	struct connection *connections;
	struct nfq_handle *netfilter_handle;
	struct nfq_q_handle *queue_handle;
	uint16_t queue_number;
	uint32_t external_address;
	uint32_t internal_address;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Filter the packets sent to a Netfilter QUEUE target "
		"through TCPR,\nenabling an application to recover and "
		"migrate its TCP connections.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -i HOST    Let the application bind to HOST.\n");
	fprintf(stderr, "  -e HOST    Let the peer connect to HOST.\n");
	fprintf(stderr, "  -q NUMBER  "
		"Get packets from netfilter queue NUMBER.\n");
	fprintf(stderr, "  -?         Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(struct filter *f, int argc, char **argv)
{
	int o;

	f->connections = NULL;
	f->internal_host = "127.0.0.2";
	f->external_host = "127.0.0.1";
	f->capture_size = 65536;
	f->max_events = 256;
	f->queue_number = 0;

	while ((o = getopt(argc, argv, "i:e:q:?")) != -1)
		switch (o) {
		case 'i':
			f->internal_host = optarg;
			break;
		case 'e':
			f->external_host = optarg;
			break;
		case 'q':
			f->queue_number = (uint16_t)atoi(optarg);
			break;
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

static int is_from_peer(struct ip *ip, struct filter *f)
{
	return ip->ip_src.s_addr != f->internal_address;
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

static void externalize_source(struct ip *ip, struct tcphdr *tcp,
			       struct filter *f)
{
	uint32_t sum =
	    shorten(~ip->ip_src.s_addr) + shorten(f->external_address);
	ip->ip_src.s_addr = f->external_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void internalize_destination(struct ip *ip, struct tcphdr *tcp,
				    struct filter *f)
{
	uint32_t sum =
	    shorten(~ip->ip_dst.s_addr) + shorten(f->internal_address);
	ip->ip_dst.s_addr = f->internal_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void drop(int id, struct filter *f)
{
	if (nfq_set_verdict(f->queue_handle, id, NF_DROP, 0, NULL) < 0)
		fputs("Error dropping packet.\n", stderr);
}

static void deliver(int id, struct ip *ip, struct tcphdr *tcp, struct filter *f)
{
	/* FIXME: recompute MD5 signature if necessary */
	if (!tcp->th_sum)
		compute_tcp_checksum(ip, tcp);
	if (nfq_set_verdict
	    (f->queue_handle, id, NF_ACCEPT, ntohs(ip->ip_len),
	     (unsigned char *)ip) < 0)
		fputs("Error delivering packet.\n", stderr);
}

static void inject(struct ip *ip, struct filter *f)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip->ip_dst.s_addr;
	if (sendto
	    (f->raw_socket, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&addr,
	     sizeof(addr)) < 0)
		perror("Injecting packet");
}

static void make_packet(struct ip *ip, struct tcphdr *tcp, uint32_t src,
			uint32_t dst)
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
	/* FIXME: add MD5 signature if necessary */
	compute_ip_checksum(ip);
	compute_tcp_checksum(ip, tcp);
}

static void reset(struct connection *c, struct filter *f)
{
	struct {
		struct ip ip;
		struct tcphdr tcp;
	} packet;
	tcpr_reset(&packet.tcp, c->state);
	make_packet(&packet.ip, &packet.tcp, c->peer_address.sin_addr.s_addr, f->internal_address);
	inject(&packet.ip, f);
}

static void recover(struct connection *c, struct filter *f)
{
	struct {
		struct ip ip;
		struct tcphdr tcp;
	} packet;
	tcpr_recover(&packet.tcp, c->state);
	make_packet(&packet.ip, &packet.tcp, c->peer_address.sin_addr.s_addr, f->internal_address);
	inject(&packet.ip, f);
}

static void update(struct connection *c, struct filter *f)
{
	struct {
		struct ip ip;
		struct tcphdr tcp;
	} packet;
	tcpr_update(&packet.tcp, c->state);
	make_packet(&packet.ip, &packet.tcp, f->external_address, c->peer_address.sin_addr.s_addr);
	inject(&packet.ip, f);
}

static int compare_connections(const void *a, const void *b)
{
	const struct connection *c = a;
	const struct connection *d = b;

	if (c->peer_address.sin_addr.s_addr < d->peer_address.sin_addr.s_addr)
		return -1;
	if (d->peer_address.sin_addr.s_addr < c->peer_address.sin_addr.s_addr)
		return 1;
	if (c->peer_address.sin_port < d->peer_address.sin_port)
		return -1;
	if (d->peer_address.sin_port < c->peer_address.sin_port)
		return 1;
	if (c->port < d->port)
		return -1;
	if (d->port < c->port)
		return 1;
	return 0;
}

static struct tcpr *get_state(struct sockaddr_in *peer_address, uint16_t port, int create)
{
	char host[INET_ADDRSTRLEN];
	char path[sizeof(state_path_format) + sizeof(host) + 10];
	int flags;
	int fd;
	struct tcpr *state;

	inet_ntop(AF_INET, &peer_address->sin_addr, host, sizeof(host));
	sprintf(path, state_path_format, host, ntohs(peer_address->sin_port), ntohs(port));

	flags = O_RDWR;
	if (create)
		flags |= O_CREAT;
	fd = open(path, flags, 0600);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, sizeof(*state)) < 0) {
		close(fd);
		return NULL;
	}

	flags = PROT_READ | PROT_WRITE;
	state = mmap(NULL, sizeof(*state), flags, MAP_SHARED, fd, 0);
	close(fd);
	return state == MAP_FAILED ? NULL : state;
}

static void teardown_state(struct tcpr *state)
{
	munmap(state, sizeof(*state));
}

static void unlink_state(struct sockaddr_in *peer_address, uint16_t port)
{
	char host[INET_ADDRSTRLEN];
	char path[sizeof(state_path_format) + sizeof(host) + 10];

	inet_ntop(AF_INET, &peer_address->sin_addr, host, sizeof(host));
	sprintf(path, state_path_format, host, ntohs(peer_address->sin_port), ntohs(port));
	unlink(path);
}

static void setup_ctl_address(struct sockaddr_un *ctl_address, struct sockaddr_in *peer_address, uint16_t port)
{
	char host[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &peer_address->sin_addr, host, sizeof(host));
	memset(ctl_address, 0, sizeof(*ctl_address));
	ctl_address->sun_family = AF_UNIX;
	sprintf(ctl_address->sun_path, ctl_path_format, host, ntohs(peer_address->sin_port), ntohs(port));
}

static int get_ctl(struct sockaddr_un *ctl_address)
{
	int s;

	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	unlink(ctl_address->sun_path);
	if (bind(s, (struct sockaddr *)ctl_address, sizeof(*ctl_address)) < 0) {
		close(s);
		return -1;
	}
	return s;
}

static void teardown_ctl(int s)
{
	close(s);
}

static int setup_connection_events(struct connection *c, struct filter *f)
{
	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.ptr = c;
	return epoll_ctl(f->epoll_fd, EPOLL_CTL_ADD, c->ctl_socket, &event);
}

static void teardown_connection(struct connection *c, struct filter *f)
{
	tdelete(c, (void **)&f->connections, compare_connections);
	teardown_state(c->state);
	teardown_ctl(c->ctl_socket);
	unlink_state(&c->peer_address, c->port);
	unlink(c->ctl_address.sun_path);
}

static struct connection *get_connection(struct ip *ip, struct tcphdr *tcp,
					 struct filter *f)
{
	struct connection key;
	struct connection *c;
	struct connection **node;

	key.peer_address.sin_family = AF_INET;
	if (is_from_peer(ip, f)) {
		key.peer_address.sin_addr.s_addr = ip->ip_src.s_addr;
		key.peer_address.sin_port = tcp->th_sport;
		key.port = tcp->th_dport;
	} else {
		key.peer_address.sin_addr.s_addr = ip->ip_dst.s_addr;
		key.peer_address.sin_port = tcp->th_dport;
		key.port = tcp->th_sport;
	}

	node = tfind(&key, (void **)&f->connections, compare_connections);
	if (node)
		return *node;

	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	c->peer_address.sin_family = key.peer_address.sin_family;
	c->peer_address.sin_addr.s_addr = key.peer_address.sin_addr.s_addr;
	c->peer_address.sin_port = key.peer_address.sin_port;
	c->port = key.port;

	c->state = get_state(&c->peer_address, c->port, !(tcp->th_flags & TH_ACK));
	if (!c->state) {
		free(c);
		return NULL;
	}

	setup_ctl_address(&c->ctl_address, &c->peer_address, c->port);
	c->ctl_socket = get_ctl(&c->ctl_address);
	if (c->ctl_socket < 0) {
		teardown_state(c->state);
		free(c);
		return NULL;
	}

	if (setup_connection_events(c, f) < 0) {
		teardown_state(c->state);
		teardown_ctl(c->ctl_socket);
		free(c);
		return NULL;
	}

	return c;
}

static int handle_packet(struct nfq_q_handle *q, struct nfgenmsg *m,
			 struct nfq_data *d, void *a)
{
	size_t tcp_size;
	struct connection *c;
	struct filter *f = a;
	struct ip *ip;
	struct tcphdr *tcp;
	int id;

	(void)q;
	(void)m;

	id = ntohl((nfq_get_msg_packet_hdr(d))->packet_id);
	nfq_get_payload(d, (char **)&ip);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ip_hl);
	tcp_size = htons(ip->ip_len) - ip->ip_hl * 4;

	c = get_connection(ip, tcp, f);
	if (!c) {
		fprintf(stderr, "Could not find connection for packet.\n");
		drop(id, f);
		return 0;
	}

	if (is_from_peer(ip, f)) {
		tcpr_filter_peer(c->state, tcp, tcp_size);
		internalize_destination(ip, tcp, f);
		deliver(id, ip, tcp, f);
	} else {
		switch (tcpr_filter(c->state, tcp, tcp_size)) {
		case TCPR_DELIVER:
			externalize_source(ip, tcp, f);
			deliver(id, ip, tcp, f);
			break;
		case TCPR_DROP:
			drop(id, f);
			break;
		case TCPR_RESET:
			drop(id, f);
			reset(c, f);
			break;
		case TCPR_RECOVER:
			drop(id, f);
			recover(c, f);
			break;
		}
	}

	if (c->state->saved.done)
		teardown_connection(c, f);
	return 0;
}

static void setup_netfilter(struct filter *f)
{
	f->netfilter_handle = nfq_open();
	if (!f->netfilter_handle) {
		fputs("Error opening the queue interface.\n", stderr);
		exit(EXIT_FAILURE);
	}

	nfq_unbind_pf(f->netfilter_handle, AF_INET);
	if (nfq_bind_pf(f->netfilter_handle, AF_INET) < 0) {
		fputs("Error binding the queue handler.\n", stderr);
		exit(EXIT_FAILURE);
	}

	f->queue_handle =
	    nfq_create_queue(f->netfilter_handle, f->queue_number,
			     handle_packet, f);
	if (!f->queue_handle) {
		fputs("Error creating the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}

	if (nfq_set_mode(f->queue_handle, NFQNL_COPY_PACKET, f->capture_size) <
	    0) {
		fputs("Error setting up the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}

	f->netfilter_fd = nfq_fd(f->netfilter_handle);
}

static void setup_events(struct filter *f)
{
	struct epoll_event event;

	f->epoll_fd = epoll_create1(0);
	if (f->epoll_fd < 0) {
		perror("Error opening epoll");
		exit(EXIT_FAILURE);
	}

	event.events = EPOLLIN;
	event.data.ptr = f;
	if (epoll_ctl(f->epoll_fd, EPOLL_CTL_ADD, f->netfilter_fd, &event) < 0) {
		perror("Error adding to epoll");
		exit(EXIT_FAILURE);
	}
}

static void setup_addresses(struct filter *f)
{
	struct addrinfo *ai;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(f->internal_host, NULL, &hints, &ai);
	if (err) {
		fprintf(stderr, "Error resolving internal address: %s\n",
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	f->internal_address =
	    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ai);

	err = getaddrinfo(f->external_host, NULL, &hints, &ai);
	if (err) {
		fprintf(stderr, "Error resolving internal address: %s\n",
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	f->external_address =
	    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ai);
}

static void setup_raw_socket(struct filter *f)
{
	f->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (f->raw_socket < 0) {
		perror("Opening raw socket");
		exit(EXIT_FAILURE);
	}
}

static void handle_event(struct filter *f, struct epoll_event *e)
{
	char data[f->capture_size];
	ssize_t size;

	if (e->data.ptr == f) {
		size = read(f->netfilter_fd, data, sizeof(data));
		if (size < 0) {
			perror("Error reading a packet");
			exit(EXIT_FAILURE);
		}
		nfq_handle_packet(f->netfilter_handle, data, size);
	} else {
		struct connection *c = e->data.ptr;
		size = read(c->ctl_socket, data, sizeof(data));
		update(c, f);
		if (c->state->saved.done)
			teardown_connection(c, f);
	}
}

static void handle_events(struct filter *f)
{
	int i;
	int n;
	sigset_t sigs;
	struct epoll_event events[f->max_events];

	sigemptyset(&sigs);
	while (!finished) {
		n = epoll_pwait(f->epoll_fd, events, f->max_events, -1, &sigs);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("Error waiting for events");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < n; i++)
			handle_event(f, &events[i]);
	}
}

static void teardown_raw_socket(struct filter *f)
{
	close(f->raw_socket);
}

static void teardown_events(struct filter *f)
{
	close(f->epoll_fd);
}

static void teardown_netfilter(struct filter *f)
{
	nfq_destroy_queue(f->queue_handle);
	nfq_close(f->netfilter_handle);
}

int main(int argc, char **argv)
{
	struct filter f;

	handle_options(&f, argc, argv);

	setup_signals();
	setup_priority();

	setup_addresses(&f);

	setup_netfilter(&f);
	setup_events(&f);
	setup_raw_socket(&f);

	/* FIXME: logging and statistics */
	handle_events(&f);

	teardown_raw_socket(&f);
	teardown_events(&f);
	teardown_netfilter(&f);

	return EXIT_SUCCESS;
}
