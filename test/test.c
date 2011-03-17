#include "test.h"

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

FILE *external_log;
FILE *internal_log;
int tun;

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

void expect(uint32_t actual, uint32_t expected, const char *s)
{
	if (actual != expected) {
		fprintf(stderr, "%s %" PRIu32 " (expected %" PRIu32 ").\n",
			s, actual, expected);
		exit(EXIT_FAILURE);
	}
}

uint32_t shorten(uint32_t n)
{
	return (n >> 16) + (n & 0xffff);
}

uint32_t checksum(uint16_t *data, size_t size)
{
	uint32_t sum;
	for (sum = 0; size > 1; size -= 2)
		sum += *data++;
	if (size)
		sum += (uint16_t)*(uint8_t *)data << 16;
	return sum;
}

void compute_ip_checksum(struct ip *ip)
{
	uint32_t sum = checksum((uint16_t *)ip, ip->ip_hl * 4);
	ip->ip_sum = ~shorten(shorten(sum));
}

void compute_tcp_checksum(struct ip *ip, struct tcphdr *tcp)
{
	uint32_t size = ntohs(ip->ip_len) - ip->ip_hl * 4;
	uint32_t sum = checksum((uint16_t *)tcp, size)
			+ shorten(ip->ip_dst.s_addr)
			+ shorten(ip->ip_src.s_addr)
			+ htons(ip->ip_p + size);
	tcp->th_sum = ~shorten(shorten(sum));
}

void compute_udp_checksum(struct ip *ip, struct udphdr *udp)
{
	uint32_t size = ntohs(ip->ip_len) - ip->ip_hl * 4;
	uint32_t sum = checksum((uint16_t *)udp, size)
			+ shorten(ip->ip_dst.s_addr)
			+ shorten(ip->ip_src.s_addr)
			+ htons(ip->ip_p + size);
	udp->uh_sum = ~shorten(shorten(sum));
}

void send_segment(FILE *log, uint32_t saddr, uint32_t daddr,
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

void recv_segment(FILE *log, uint32_t saddr, uint32_t daddr,
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

void send_update(uint32_t saddr, uint32_t daddr,
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

void recv_update(uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport,
				uint32_t peer_address, uint32_t address,
				uint16_t peer_port, uint16_t port,
				uint32_t peer_ack, uint32_t ack,
				uint16_t peer_mss, uint8_t peer_ws,
				uint32_t delta, uint32_t flags)
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
	if (flags & TCPR_HAVE_PEER_MSS)
		expect(ntohs(update->tcpr.peer_mss), peer_mss,
			"Update peer maximum segment size");
	if (flags & TCPR_HAVE_PEER_WS)
		expect(update->tcpr.peer_ws, peer_ws,
			"Update peer window scaling");
	expect(ntohl(update->tcpr.ack), ack,
		"Update acknowledgment");
	expect(update->tcpr.delta, delta, "Update delta");
	expect(update->tcpr.flags, flags, "Update flags");
}
