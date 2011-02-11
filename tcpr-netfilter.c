#include "tcpr.h"

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

struct state {
	struct state *next;
	uint32_t peer_address;
	struct tcpr_state tcpr;
};

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

struct segment {
	struct ip ip;
	struct tcphdr tcp;
};

struct datagram {
	struct ip ip;
	struct udphdr udp;
	struct update update;
};

struct log_header {
	uint32_t magic;
	uint16_t major;
	uint16_t minor;
	uint32_t zone;
	uint32_t sigfigs;
	uint32_t caplen;
	uint32_t network;
};

struct log_packet {
	uint32_t seconds;
	uint32_t microseconds;
	uint32_t captured;
	uint32_t size;
};

static const int drop_flags = TCPR_SPURIOUS_FIN | TCPR_SPURIOUS_RST
	| TCPR_RECOVERY | TCPR_NO_STATE | TCPR_DUPLICATE_ACK;
static const int update_flags =
	TCPR_PEER_ACK | TCPR_CLOSING | TCPR_RECOVERY | TCPR_NO_STATE;

static int debugging;
static unsigned long packets;
static unsigned long segments;
static unsigned long updates;
static unsigned long delivered;
static unsigned long injected;
static unsigned long errors;
static long ticks_per_second;

static int raw_socket;
static uint32_t internal_address;
static uint32_t external_address;
static uint16_t internal_port;
static uint16_t external_port;

static FILE *internal_log;
static FILE *external_log;
static FILE *state_log;

static void log_packet(struct ip *ip, FILE *log)
{
	struct timespec tp;
	size_t size = ntohs(ip->ip_len);
	struct log_packet p;

	clock_gettime(CLOCK_REALTIME, &tp);
	p.seconds = tp.tv_sec;
	p.microseconds = tp.tv_nsec / 1000;
	p.captured = size;
	p.size = size;

	fwrite(&p, sizeof(p), 1, log);
	fwrite(ip, size, 1, log);
}

static void log_state(struct state *s)
{
	struct timespec tp;

	clock_gettime(CLOCK_REALTIME, &tp);
        fprintf(state_log, "%lf:\n",  (double)tp.tv_sec
                                        + (double)tp.tv_nsec / 1000000000.0);
	fprintf(state_log, "Packet %lu:\n", packets - 1);
	fprintf(state_log, "  Peer address:        %" PRIx32 "\n",
						ntohl(s->peer_address));
	fprintf(state_log, "  Peer port:           %" PRIu16 "\n",
						ntohs(s->tcpr.peer_port));
	fprintf(state_log, "  Port:                %" PRIu16 "\n",
						ntohs(s->tcpr.port));
	if (s->tcpr.flags & TCPR_HAVE_PEER_ACK)
		fprintf(state_log, "  Peer acknowledgment: %" PRIu32 "\n",
						ntohl(s->tcpr.peer_ack));
	else
		fprintf(state_log, "  Peer acknowledgment: None.\n");
	if (s->tcpr.flags & TCPR_HAVE_PEER_FIN)
		fprintf(state_log, "  Peer final sequence: %" PRIu32 "\n",
						ntohl(s->tcpr.peer_fin));
	else
		fprintf(state_log, "  Peer final sequence: None.\n");
	fprintf(state_log, "  Peer window:         %" PRIu16 "\n",
						ntohs(s->tcpr.peer_win));
	if (s->tcpr.flags & TCPR_HAVE_ACK)
		fprintf(state_log, "  Acknowledgment:      %" PRIu32 "\n",
						ntohl(s->tcpr.ack));
	else
		fprintf(state_log, "  Acknowledgment:      None.\n");
	if (s->tcpr.flags & TCPR_HAVE_FIN)
		fprintf(state_log, "  Final sequence:      %" PRIu32 "\n",
						ntohl(s->tcpr.fin));
	else
		fprintf(state_log, "  Final sequence:      None.\n");
	fprintf(state_log, "  Sequence:            %" PRIu32 "\n",
						ntohl(s->tcpr.seq));
	fprintf(state_log, "  Window:              %" PRIu16 "\n",
						ntohs(s->tcpr.win));
	fprintf(state_log, "  Delta:               %" PRIu32 "\n",
						s->tcpr.delta);
	if (s->tcpr.flags & TCPR_DONE_READING)
		fprintf(state_log, "  Done reading.\n");
	if (s->tcpr.flags & TCPR_DONE_WRITING)
		fprintf(state_log, "  Done writing.\n");
}

static void log_statistics(void)
{
	struct tms tms;

	times(&tms);
	fprintf(stderr, "%lf user, %lf system:\n",
			(double)tms.tms_utime/(double)ticks_per_second,
			(double)tms.tms_stime/(double)ticks_per_second);
	fprintf(stderr, "  %lu packets (%lu updates, %lu segments)\n",
			packets, updates, segments); 
	fprintf(stderr, "  %lu delivered, %lu injected\n",
			delivered, injected);
	fprintf(stderr, "  %lu errors\n", errors);
}

static uint32_t shorten(uint32_t n)
{
        return (n >> 16) + (n & 0xffff);
}

static uint32_t rotate(uint32_t n, size_t bits)
{
	return n << bits | n >> (32 - bits);
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

static void compute_udp_checksum(struct ip *ip, struct udphdr *udp)
{
	uint32_t size = ntohs(ip->ip_len) - ip->ip_hl * 4;
	uint32_t sum = checksum((uint16_t *)udp, size)
			+ shorten(ip->ip_dst.s_addr)
			+ shorten(ip->ip_src.s_addr)
			+ htons(ip->ip_p + size);
	udp->uh_sum = ~shorten(shorten(sum));
}

static struct state **get_bucket(uint32_t a, uint32_t b, uint32_t c)
{
	static struct state *buckets[1 << 8];
	/* <http://burtleburtle.net/bob/c/lookup3.c> */
	c ^= b, c -= rotate(b, 14);
	a ^= c, a -= rotate(c, 11);
	b ^= a, b -= rotate(a, 25);
	c ^= b, c -= rotate(b, 16);
	a ^= c, a -= rotate(c, 4);
	b ^= a, b -= rotate(a, 14);
	c ^= b, c -= rotate(b, 24);
	return &buckets[c & ((sizeof(buckets) / sizeof(*buckets)) - 1)];
}

static struct state *get_state(uint32_t peer_address, uint16_t peer_port,
				uint16_t port)
{
	struct state **bucket = get_bucket(peer_address, external_address,
						peer_port << 16 | port);
	struct state *state;
	for (state = *bucket; state; state = state->next)
		if (state->peer_address == peer_address
				&& state->tcpr.peer_port == peer_port
				&& state->tcpr.port == port)
			return state;
	state = malloc(sizeof(*state));
	if (!state)
		return NULL;
	memset(&state->tcpr, 0, sizeof(state->tcpr));
	state->peer_address = peer_address;
	state->tcpr.peer_port = peer_port;
	state->tcpr.port = port;
	state->next = *bucket;
	*bucket = state;
	return state;
}

static void remove_state(uint32_t peer_address, uint16_t peer_port,
				uint16_t port)
{
	struct state **bucket = get_bucket(peer_address, external_address,
						peer_port << 16 | port);
	struct state *state;
	for (state = *bucket; state; bucket = &state->next, state = *bucket)
		if (state->peer_address == peer_address
				&& state->tcpr.peer_port == peer_port
				&& state->tcpr.port == port) {
			*bucket = state->next;
			free(state);
			return;
		}
}

static void set_external_source(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t sum = shorten(~ip->ip_src.s_addr) + shorten(external_address);
	ip->ip_src.s_addr = external_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void set_internal_destination(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t sum = shorten(~ip->ip_dst.s_addr) + shorten(internal_address);
	ip->ip_dst.s_addr = internal_address;
	ip->ip_sum = ~shorten(shorten((ip->ip_sum ^ 0xffff) + sum));
	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten((tcp->th_sum ^ 0xffff) + sum));
}

static void drop(struct nfq_q_handle *q, int id)
{
	if (nfq_set_verdict(q, id, NF_DROP, 0, NULL) < 0)
		fputs("Error dropping packet.\n", stderr);
}

static void deliver(struct nfq_q_handle *q, int id, struct ip *ip,
			struct tcphdr *tcp, FILE *log)
{
	++delivered;
	if (!tcp->th_sum)
		compute_tcp_checksum(ip, tcp);
	if (debugging)
		log_packet(ip, log);
	if (nfq_set_verdict(q, id, NF_ACCEPT, ntohs(ip->ip_len),
				(unsigned char *)ip) < 0)
		fputs("Error delivering packet.\n", stderr);
}

static void inject(struct ip *ip, FILE *log)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	++injected;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip->ip_dst.s_addr;
	if (debugging)
		log_packet(ip, log);
        if (sendto(raw_socket, ip, ntohs(ip->ip_len), 0,
			(struct sockaddr *)&addr, len) < 0)
                perror("Injecting packet");
}

static void make_packet(struct ip *ip, uint16_t size,
			uint32_t src, uint32_t dst, int protocol)
{
	ip->ip_hl = sizeof(*ip) / 4;
	ip->ip_v = 4;
	ip->ip_tos = 0;
	ip->ip_len = htons(size);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = protocol;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = src;
	ip->ip_dst.s_addr = dst;
}

static void inject_acknowledgment(struct state *state)
{
	struct segment s;
	make_packet(&s.ip, sizeof(s), external_address, state->peer_address,
			IPPROTO_TCP);
	tcpr_make_acknowledgment(&s.tcp, &state->tcpr);
	compute_ip_checksum(&s.ip);
	compute_tcp_checksum(&s.ip, &s.tcp);
	inject(&s.ip, external_log);
}

static void inject_handshake(struct state *state)
{
	struct segment s;
	make_packet(&s.ip, sizeof(s), state->peer_address, internal_address,
			IPPROTO_TCP);
	tcpr_make_handshake(&s.tcp, &state->tcpr);
	compute_ip_checksum(&s.ip);
	compute_tcp_checksum(&s.ip, &s.tcp);
	inject(&s.ip, internal_log);
}

static void inject_reset(struct state *state)
{
	struct segment s;
	make_packet(&s.ip, sizeof(s), state->peer_address, internal_address,
			IPPROTO_TCP);
	tcpr_make_reset(&s.tcp, &state->tcpr);
	compute_ip_checksum(&s.ip);
	compute_tcp_checksum(&s.ip, &s.tcp);
	inject(&s.ip, internal_log);
}

static void inject_update(struct state *state)
{
	struct datagram s;
	make_packet(&s.ip, sizeof(s), external_address, internal_address,
			IPPROTO_UDP);
	s.udp.uh_sport = external_port;
	s.udp.uh_dport = internal_port;
	s.udp.uh_ulen = htons(sizeof(s.udp) + sizeof(s.update));
	s.udp.uh_sum = 0;
	s.update.peer_address = state->peer_address;
	s.update.address = internal_address;
	tcpr_make_update(&s.update.tcpr, &state->tcpr);
	compute_ip_checksum(&s.ip);
	compute_udp_checksum(&s.ip, &s.udp);
	inject(&s.ip, internal_log);
}

static int passthrough(struct nfq_q_handle *q, struct nfgenmsg *m,
				  struct nfq_data *d, void *a)
{
	struct ip *ip;
	int id;

	(void)m;
	(void)a;

	id = ntohl((nfq_get_msg_packet_hdr(d))->packet_id);
	nfq_get_payload(d, (char **)&ip);
	++delivered;
	if (nfq_set_verdict(q, id, NF_ACCEPT, ntohs(ip->ip_len),
				(unsigned char *)ip) < 0)
		fputs("Error delivering packet.\n", stderr);
	return 0;
}

static int handle_packet(struct nfq_q_handle *q, struct nfgenmsg *m,
				  struct nfq_data *d, void *a)
{
	int flags;
	int id;
	struct ip *ip;
	struct state *s;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct update *update;

	(void)m;
	(void)a;

	id = ntohl((nfq_get_msg_packet_hdr(d))->packet_id);
	nfq_get_payload(d, (char **)&ip);

	if (ip->ip_p == IPPROTO_UDP) {
		if (debugging)
			log_packet(ip, internal_log);
		++updates;
		udp = (struct udphdr *)((uint32_t *)ip + ip->ip_hl);
		update = (struct update *)(udp + 1);
		s = get_state(update->peer_address, update->tcpr.peer_port,
				update->tcpr.port);
		if (!s) {
			++errors;
			drop(q, id);
			return 0;
		}

		internal_address = update->address;
		flags = tcpr_handle_update(&s->tcpr, &update->tcpr);
		if (debugging)
			log_state(s);
		drop(q, id);
		if (flags & TCPR_CLOSED) {
			remove_state(update->peer_address,
					update->tcpr.peer_port,
					update->tcpr.port);
			return 0;
		}
		if (flags & update_flags)
			inject_update(s);
		if (flags & TCPR_UPDATE_ACK)
			inject_acknowledgment(s);
		return 0;
        }

	++segments;
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ip_hl);
	if (ip->ip_dst.s_addr == external_address) {
		if (debugging)
			log_packet(ip, external_log);
		s = get_state(ip->ip_src.s_addr, tcp->th_sport, tcp->th_dport);
		if (!s) {
			++errors;
			drop(q, id);
			return 0;
		}

		flags = tcpr_handle_segment_from_peer(&s->tcpr, tcp,
					htons(ip->ip_len) - ip->ip_hl * 4);
		if (debugging)
			log_state(s);
		if (flags & drop_flags) {
			drop(q, id);
		} else {
			set_internal_destination(ip, tcp);
			deliver(q, id, ip, tcp, internal_log);
		}
		if (flags & update_flags)
			inject_update(s);
		return 0;
        } else {
		if (debugging)
			log_packet(ip, internal_log);
		internal_address = ip->ip_src.s_addr;
		s = get_state(ip->ip_dst.s_addr, tcp->th_dport, tcp->th_sport);
		if (!s) {
			++errors;
			drop(q, id);
			return 0;
		}

		flags = tcpr_handle_segment(&s->tcpr, tcp,
					htons(ip->ip_len) - ip->ip_hl * 4);
		if (debugging)
			log_state(s);
		if (flags & drop_flags) {
			drop(q, id);
		} else {
			set_external_source(ip, tcp);
			deliver(q, id, ip, tcp, external_log);
		}
		if (flags & TCPR_SPURIOUS_FIN)
			inject_reset(s);
		if (flags & TCPR_RECOVERY)
			inject_handshake(s);
		if (flags & update_flags)
			inject_update(s);
		return 0;
	}
}

static void terminate(int s)
{
	(void)s;
}

static void split_address(char *address, const char **host, const char **port)
{
	char *tmp = strrchr(address, ':');
	if (tmp) {
		*tmp++ = '\0';
		*port = *tmp ? tmp : NULL;
	} else {
		*port = NULL;
	}
	*host = *address ? address : NULL;
}

int main(int argc, char **argv)
{
	const char *filter_host = NULL;
	const char *filter_port = NULL;
	const char *application_host = NULL;
	const char *application_port = NULL;
	char packet[65536];
	int fd;
	int ret;
	nfq_callback *handler = handle_packet;
	ssize_t size;
	struct addrinfo *ai;
	struct addrinfo hints;
	struct nfq_handle *h;
	struct nfq_q_handle *q;
	struct log_header log_header;
	unsigned long statistics_interval = 0;
	unsigned long statistics_at_end = 0;
	struct sigaction sa;
	struct sigaction old;

	while ((ret = getopt(argc, argv, "a:f:s:dp?")) != -1)
		switch (ret) {
		case 'a':
			split_address(optarg, &application_host,
						&application_port);
			break;
		case 'f':
			split_address(optarg, &filter_host, &filter_port);
			break;
		case 's':
			statistics_interval = (unsigned)atol(optarg);
			statistics_at_end = 1;
			break;
		case 'd':
			debugging++;
			break;
		case 'p':
			handler = passthrough;
			break;
		default:
			fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
			fprintf(stderr, "  -a HOST:[PORT]  "
				"Send updates to the specified address.\n");
			fprintf(stderr, "  -f HOST:[PORT]  "
				"Receive updates at the specified address.\n");
			fprintf(stderr, "  -s INTERVAL     "
				"Print statistics every INTERVAL packets.\n");
			fprintf(stderr, "  -d              "
				"Print debugging messages and write logs.\n");
			fprintf(stderr, "  -p              "
				"Pass packets through without processing.\n");
			fprintf(stderr, "  -?              "
				"Print this help message and exit.\n");
			exit(EXIT_FAILURE);
		}

	if (!filter_port)
		filter_port = application_port ? application_port : "7777";
	if (!application_port)
		application_port = filter_port;

	ticks_per_second = sysconf(_SC_CLK_TCK);

	if (debugging) {
		state_log = fopen("state.log", "w");
		if (!state_log) {
			perror("Opening state log");
			exit(EXIT_FAILURE);
		}

		log_header.magic = 0xa1b2c3d4;
		log_header.major = 2;
		log_header.minor = 4;
		log_header.zone = 0;
		log_header.sigfigs = 0;
		log_header.caplen = sizeof(packet);
		log_header.network = 101;

		internal_log = fopen("internal.pcap", "w");
		if (!internal_log) {
			perror("Opening internal log");
			exit(EXIT_FAILURE);
		}
		fwrite(&log_header, sizeof(log_header), 1, internal_log);
		fflush(internal_log);

		external_log = fopen("external.pcap", "w");
		if (!external_log) {
			perror("Opening external log");
			exit(EXIT_FAILURE);
		}
		fwrite(&log_header, sizeof(log_header), 1, external_log);
		fflush(external_log);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	ret = getaddrinfo(application_host, application_port, &hints, &ai);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	internal_address = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	internal_port = ((struct sockaddr_in *)ai->ai_addr)->sin_port;
	freeaddrinfo(ai);
	ret = getaddrinfo(filter_host, filter_port, &hints, &ai);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	external_address = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	external_port = ((struct sockaddr_in *)ai->ai_addr)->sin_port;
	freeaddrinfo(ai);

	raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_socket < 0) {
		perror("Opening raw socket");
		exit(EXIT_FAILURE);
	}

	h = nfq_open();
	if (!h) {
		fputs("Error opening the queue interface.\n", stderr);
		exit(EXIT_FAILURE);
	}
	nfq_unbind_pf(h, AF_INET);
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fputs("Error binding the queue handler.\n", stderr);
		exit(EXIT_FAILURE);
	}
	q = nfq_create_queue(h, 0, handler, NULL);
	if (!q) {
		fputs("Error creating the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}
	if (nfq_set_mode(q, NFQNL_COPY_PACKET, sizeof(packet)) < 0) {
		fputs("Error setting up the incoming queue.\n", stderr);
		exit(EXIT_FAILURE);
	}

	memset(&sa, 0, sizeof(sa));
	memset(&old, 0, sizeof(old));
	sa.sa_handler = terminate;
	if (sigaction(SIGINT, &sa, &old) < 0) {
		perror("Setting up signal handling");
		exit(EXIT_FAILURE);
	}

	fd = nfq_fd(h);
	for (;;) {
		size = read(fd, packet, sizeof(packet));
		if (size < 0) {
			if (errno == EINTR)
				break;
			perror("Reading packet");
			++errors;
		} else {
			++packets;
			nfq_handle_packet(h, packet, size);
		}
		if (statistics_interval && packets % statistics_interval == 0)
			log_statistics();
	}

	if (statistics_at_end)
		log_statistics();

	if (close(raw_socket) < 0) {
		perror("Closing raw socket");
		exit(EXIT_FAILURE);
	}

	nfq_destroy_queue(q);
	nfq_close(h);

	if (debugging) {
		fclose(internal_log);
		fclose(external_log);
		fclose(state_log);
	}

	return EXIT_SUCCESS;
}
