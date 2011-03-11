#include <tcpr.h>

#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SNAPLEN 65536

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

static FILE *external_log;
static FILE *internal_log;
static int tun;

int open_tun(char *device)
{
	int f;
	struct ifreq r;

	if ((f = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Opening TUN device");
		exit(EXIT_FAILURE);
	}

	memset(&r, 0, sizeof(r));
	r.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(r.ifr_name, device, IFNAMSIZ);
	if (ioctl(f, TUNSETIFF, &r) < 0) {
		perror("Setting TUN interface");
		exit(EXIT_FAILURE);
	}

	return f;
}

FILE *open_log(char *file)
{
	FILE *f;
	static const struct {
		uint32_t magic;
		uint16_t major;
		uint16_t minor;
		uint32_t zone;
		uint32_t sigfigs;
		uint32_t caplen;
		uint32_t network;
	} h = { 0xa1b2c3d4, 2, 4, 0, 0, SNAPLEN, 101 };

	f = fopen(file, "w");
	if (!f) {
		perror("Opening log file");
		exit(EXIT_FAILURE);
	}
	
	if (!fwrite(&h, sizeof(h), 1, f)) {
		perror("Writing log file header");
		exit(EXIT_FAILURE);
	}

	fflush(f);
	return f;
}

void log_packet(FILE *f, const char *packet, size_t size)
{
	struct timespec t;
	struct {
		uint32_t seconds;
		uint32_t microseconds;
		uint32_t captured;
		uint32_t size;
	} h;

	clock_gettime(CLOCK_REALTIME, &t);
	h.seconds = t.tv_sec;
	h.microseconds = t.tv_nsec / 1000;
	h.captured = size;
	h.size = size;
	if (!fwrite(&h, sizeof(h), 1, f)) {
		perror("Writing log packet header");
		exit(EXIT_FAILURE);
	}

	if (!fwrite(packet, size, 1, f)) {
		perror("Logging packet");
		exit(EXIT_FAILURE);
	}

	fflush(f);
}

static void expect(uint32_t actual, uint32_t expected, const char *s)
{
	if (actual != expected) {
		fprintf(stderr, "%s %" PRIu32 " (expected %" PRIu32 ").\n",
			s, actual, expected);
		exit(EXIT_FAILURE);
	}
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

static void compute_udp_checksum(struct ip *ip, struct udphdr *udp)
{
	uint32_t size = ntohs(ip->ip_len) - ip->ip_hl * 4;
	uint32_t sum = checksum((uint16_t *)udp, size)
			+ shorten(ip->ip_dst.s_addr)
			+ shorten(ip->ip_src.s_addr)
			+ htons(ip->ip_p + size);
	udp->uh_sum = ~shorten(shorten(sum));
}

static void send_segment(FILE *log, uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport, uint8_t flags,
				uint32_t seq, uint32_t ack,
				size_t options_size, const char *options,
				size_t payload_size, const char *payload)
{
	char packet[SNAPLEN];
	struct ip *ip;
	struct tcphdr *tcp;
	size_t size = sizeof(*ip) + sizeof(*tcp) + options_size + payload_size;

	ip = (struct ip *)packet;
	ip->ip_v = 4;
	ip->ip_hl = sizeof(*ip) / 4;
	ip->ip_tos = 0;
	ip->ip_len = htons(size);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = htonl(saddr);
	ip->ip_dst.s_addr = htonl(daddr);
	compute_ip_checksum(ip);

	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ip_hl);
	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	tcp->th_seq = htonl(seq);
	tcp->th_ack = htonl(ack);
	tcp->th_off = (sizeof(*tcp) + options_size) / 4;
	tcp->th_x2 = 0;
	tcp->th_flags = flags;
	tcp->th_win = htons(65535);
	tcp->th_sum = 0;
	tcp->th_urp = 0;
	memcpy(tcp + 1, options, options_size);
	memcpy((uint8_t *)(tcp + 1) + options_size, payload, payload_size);
	compute_tcp_checksum(ip, tcp);

	log_packet(log, packet, size);
	if (write(tun, packet, size) < 0) {
		perror("Writing packet");
		exit(EXIT_FAILURE);
	}
}

static void recv_segment(FILE *log, uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport, uint8_t flags,
				uint32_t seq, uint32_t ack,
				size_t options_size, const char *options,
				size_t payload_size, const char *payload)
{
	char packet[SNAPLEN];
	struct ip *ip;
	struct tcphdr *tcp;
	ssize_t size;

	if ((size = read(tun, packet, sizeof(packet))) < 0) {
		perror("Reading packet");
		exit(EXIT_FAILURE);
	}
	log_packet(log, packet, size);

	ip = (struct ip *)packet;
	expect(ip->ip_v, 4, "IP version");
	compute_ip_checksum(ip);
	expect(ntohs(ip->ip_sum), 0, "IP checksum");
	expect(ip->ip_p, IPPROTO_TCP, "IP protocol");
	expect(size, ntohs(ip->ip_len), "Received length");
	expect(ntohs(ip->ip_len),
		ip->ip_hl * 4 + sizeof(*tcp) + options_size + payload_size,
		"IP length");
	expect(ntohl(ip->ip_src.s_addr), saddr, "IP source");
	expect(ntohl(ip->ip_dst.s_addr), daddr, "IP destination");

	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ip_hl);
	compute_tcp_checksum(ip, tcp);
	expect(ntohs(tcp->th_sum), 0, "TCP checksum");
	expect(tcp->th_off, (sizeof(*tcp) + options_size) / 4,
		"TCP header length");
	expect(tcp->th_flags, flags, "TCP flags");
	expect(ntohl(tcp->th_seq), seq, "TCP sequence number");
	expect(ntohl(tcp->th_ack), ack, "TCP acknowledgment");
	expect(ntohs(tcp->th_sport), sport, "TCP source");
	expect(ntohs(tcp->th_dport), dport, "TCP destination");

	if (options_size && memcmp(tcp + 1, options, options_size)) {
		fprintf(stderr, "TCP options do not match.\n");
		exit(EXIT_FAILURE);
	}
	if (payload_size && memcmp((uint8_t *)(tcp + 1) + options_size,
					payload, payload_size)) {
		fprintf(stderr, "TCP payload does not match.\n");
		exit(EXIT_FAILURE);
	}
}

static void send_update(uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport,
				uint32_t peer_address, uint32_t address,
				uint16_t peer_port, uint16_t port,
				uint32_t peer_ack, uint32_t ack,
				uint32_t delta, uint32_t flags)
{
	char packet[SNAPLEN];
	struct ip *ip;
	struct udphdr *udp;
	struct update *update;
	size_t size = sizeof(*ip) + sizeof(*udp) + sizeof(*update);

	ip = (struct ip *)packet;
	ip->ip_v = 4;
	ip->ip_hl = sizeof(*ip) / 4;
	ip->ip_tos = 0;
	ip->ip_len = htons(size);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = htonl(saddr);
	ip->ip_dst.s_addr = htonl(daddr);
	compute_ip_checksum(ip);

	udp = (struct udphdr *)((uint32_t *)ip + ip->ip_hl);
	udp->uh_sport = htons(sport);
	udp->uh_dport = htons(dport);
	udp->uh_sum = 0;
	udp->uh_ulen = htons(sizeof(*udp) + sizeof(*update));
	update = (struct update *)(udp + 1);
	update->peer_address = htonl(peer_address);
	update->address = htonl(address);
	update->tcpr.peer_port = htons(peer_port);
	update->tcpr.port = htons(port);
	update->tcpr.peer_ack = htonl(peer_ack);
	update->tcpr.ack = htonl(ack);
	update->tcpr.delta = delta;
	update->tcpr.flags = flags;
	compute_udp_checksum(ip, udp);

	log_packet(internal_log, packet, size);
	if (write(tun, packet, size) < 0) {
		perror("Writing packet");
		exit(EXIT_FAILURE);
	}
}

static void recv_update(uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport,
				uint32_t peer_address, uint32_t address,
				uint16_t peer_port, uint16_t port,
				uint32_t peer_ack, uint32_t ack,
				uint32_t delta, uint32_t flags, uint16_t mss,
				uint8_t ws)
{
	char packet[SNAPLEN];
	struct ip *ip;
	struct udphdr *udp;
	struct update *update;
	ssize_t size;

	if ((size = read(tun, packet, sizeof(packet))) < 0) {
		perror("Reading packet");
		exit(EXIT_FAILURE);
	}
	log_packet(internal_log, packet, size);

	ip = (struct ip *)packet;
	expect(ip->ip_v, 4, "IP version");
	compute_ip_checksum(ip);
	expect(ntohs(ip->ip_sum), 0, "IP checksum");
	expect(ip->ip_p, IPPROTO_UDP, "IP protocol");
	expect(size, ntohs(ip->ip_len), "Received length");
	expect(ntohs(ip->ip_len),
		ip->ip_hl * 4 + sizeof(*udp) + sizeof(*update),
		"IP length");
	expect(ntohl(ip->ip_src.s_addr), saddr, "IP source");
	expect(ntohl(ip->ip_dst.s_addr), daddr, "IP destination");

	udp = (struct udphdr *)((uint32_t *)ip + ip->ip_hl);
	if (udp->uh_sum)
		compute_udp_checksum(ip, udp);
	expect(udp->uh_sum, 0, "UDP checksum");
	expect(ntohs(udp->uh_ulen), sizeof(*udp) + sizeof(*update),
		"UDP length");
	expect(ntohs(udp->uh_sport), sport, "UDP source");
	expect(ntohs(udp->uh_dport), dport, "UDP destination");

	update = (struct update *)(udp + 1);
	expect(ntohl(update->peer_address), peer_address,
		"Update peer address");
	expect(ntohl(update->address), address, "Update address");
	expect(ntohs(update->tcpr.peer_port), peer_port, "Update peer port");
	expect(ntohs(update->tcpr.port), port, "Update port");
	expect(ntohl(update->tcpr.peer_ack), peer_ack,
		"Update peer acknowledgment");
	expect(ntohl(update->tcpr.ack), ack,
		"Update acknowledgment");
	expect(update->tcpr.delta, delta, "Update delta");
	expect(update->tcpr.flags, flags, "Update flags");
	expect(ntohs(update->tcpr.mss), mss, "Update maximum segment size");
	expect(update->tcpr.ws, ws, "Update window scaling");
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;
	size_t options_size = 8;
	char *options;

	tun = open_tun("tcpr-test");
	external_log = open_log("test-external.pcap");
	internal_log = open_log("test-internal.pcap");

	options = (char *) malloc(options_size);
	*((uint32_t *)options) = htonl(0x02040640);
	*((uint32_t *)(options+4)) = htonl(0x03030200);

	fprintf(stderr, "       Peer: SYN\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_SYN, 0xdeadbeef, 0, options_size, options, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_SYN, 0xdeadbeef, 0, options_size, options, 0, NULL);

	fprintf(stderr, "Application: SYN ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_SYN | TH_ACK, 0xcafebabe, 0xdeadbeef + 1,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_SYN | TH_ACK, 0xcafebabe, 0xdeadbeef + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 1, 0, TCPR_HAVE_ACK,
			0x640, 2);

	fprintf(stderr, "Application: \"foo\"\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 4, "foo");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 4, "foo");

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"bar\"\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 4, "bar");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 4, "bar");

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: FIN (failure)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK | TH_FIN, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: RST\n");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_RST, 0xdeadbeef + 5, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\"\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: RST\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_RST, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (recovery)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef + 4, 0xfeedbead + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK,
			0, 0);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\" (retransmit)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xfeedbead + 1,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 9,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 9,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: \"quux\"\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 9,
			0, NULL, 5, "quux");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 9,
			0, NULL, 5, "quux");

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 9, 0xcafebabe + 10,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 9, 0xfeedbead + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: FIN\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 9, 0xcafebabe + 10,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 9, 0xfeedbead + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 6, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 10, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 10, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 10, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING);

	fprintf(stderr, "Application: FIN\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xfeedbead + 6, 0xdeadbeef + 10,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 10, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 10, 0xcafebabe + 11,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 10, 0xfeedbead + 7,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (TIME_WAIT)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 11, 0xdeadbeef + 10,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_TIME_WAIT, 
			0, 0);

	fprintf(stderr, "Application: update (remove state)\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 11, 0xdeadbeef + 10,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	fprintf(stderr, "Application: \"a\"\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999, 0, 0, 0, 0,
			0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead + 2, 0xbabedeed - 4,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: \"a\" (retransmit)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed - 4,
			0, NULL, 2, "a");

	fprintf(stderr, "Application: update (remove state)\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	fprintf(stderr, "Application: SYN (simultaneous recovery)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK (answer unacceptable SYN)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0, 0, 0, 
			0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (retransmit)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef + 4, 0xfeedbead + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK,
			0, 0);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update (reset)\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	if (fclose(external_log)) {
		perror("Closing external log file");
		exit(EXIT_FAILURE);
	}
	if (fclose(internal_log)) {
		perror("Closing internal log file");
		exit(EXIT_FAILURE);
	}
	if (close(tun)) {
		perror("Closing TUN device");
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}
