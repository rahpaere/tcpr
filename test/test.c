#include "test.h"
#include "../md5util.h"

#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SNAPLEN 65536

#define EXTERNAL_PCAP "-external.pcap"
#define INTERNAL_PCAP "-external.pcap"

FILE *external_log;
FILE *internal_log;
int tun;

uint16_t peer_mss = 0x0640;
uint8_t peer_ws = 0x02;
uint8_t test_options[40]; 
size_t test_options_size;

const char *filter_path = "/tmp/tcpr-filter.socket";
const char *application_path = "/tmp/tcpr-application.socket";
int update_socket;
struct sockaddr_un filter_address;

static int open_tun(const char *device)
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

static FILE *open_log(const char *file)
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

static void log_packet(FILE *f, const uint8_t *packet, size_t size)
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

static void setup_update_connection(void)
{
	struct sockaddr_un addr;

	update_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (update_socket < 0) {
		perror("Creating update socket");
		exit(EXIT_FAILURE);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, application_path, sizeof(addr.sun_path) - 1);
	unlink(application_path);
	if (bind(update_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Binding update socket");
		exit(EXIT_FAILURE);
	}

	memset(&filter_address, 0, sizeof(filter_address));
	filter_address.sun_family = AF_UNIX;
	strncpy(filter_address.sun_path, filter_path,
		sizeof(filter_address.sun_path) - 1);
}

void setup_test(const char *device, const char *log_name)
{
	char external_log_name[strlen(log_name) + strlen(EXTERNAL_PCAP) + 1];
	char internal_log_name[strlen(log_name) + strlen(INTERNAL_PCAP) + 1];

	sprintf(external_log_name, "%s" EXTERNAL_PCAP, log_name);
	sprintf(internal_log_name, "%s" INTERNAL_PCAP, log_name);

	tun = open_tun(device);
	external_log = open_log(external_log_name);
	internal_log = open_log(internal_log_name);

	test_options[test_options_size++] = TCPOPT_MAXSEG;
	test_options[test_options_size++] = 4;
	test_options[test_options_size++] = peer_mss >> 8;
	test_options[test_options_size++] = peer_mss & 0xff;

	test_options[test_options_size++] = TCPOPT_WINDOW;
	test_options[test_options_size++] = 3;
	test_options[test_options_size++] = peer_ws;

	test_options[test_options_size++] = 19;
	test_options[test_options_size++] = 18;
    test_options_size += 16;

    /*test_options[test_options_size++] = 19;
    test_options[test_options_size++] = 18;
    test_options_size += 16;*/

	if (test_options_size % 4) {
		test_options[test_options_size++] = TCPOPT_EOL;
		test_options_size += test_options_size % 4;
	}

	setup_update_connection();
}

void cleanup_test(void)
{
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
	if (close(update_socket)) {
		perror("Closing update socket");
		exit(EXIT_FAILURE);
	}
}

void setup_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
			uint16_t sport, uint16_t dport, 
			uint32_t start_seq, uint32_t start_ack,
			size_t options_size, const uint8_t *options,
			uint16_t peer_mss, uint8_t peer_ws)
{
	uint32_t option_flags = 0;
	if (peer_mss)
		option_flags |= TCPR_HAVE_PEER_MSS;
	if (peer_ws)
		option_flags |= TCPR_HAVE_PEER_WS;

	fprintf(stderr, "       Peer: SYN\n");
	send_segment(external_log, saddr, faddr, sport, dport, TH_SYN,
			start_seq, 0, options_size, options, 0, NULL);
	recv_segment(internal_log, saddr, daddr, sport, dport, TH_SYN,
			start_seq, 0, options_size, options, 0, NULL);

	fprintf(stderr, "Application: SYN ACK\n");
	send_segment(internal_log, daddr, saddr, dport, sport, TH_SYN | TH_ACK,
			start_ack, start_seq + 1, 0, NULL, 0, NULL);
	recv_segment(external_log, faddr, saddr, dport, sport, TH_SYN | TH_ACK,
			start_ack, start_seq + 1, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, saddr, faddr, sport, dport, TH_ACK,
			start_seq + 1, start_ack + 1, 0, NULL, 0, NULL);
	recv_segment(internal_log, saddr, daddr, sport, dport, TH_ACK,
			start_seq + 1, start_ack + 1, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(saddr, daddr, sport, dport, start_ack + 1, start_seq + 1,
			peer_mss, peer_ws, 0, TCPR_HAVE_ACK | option_flags);
}

void recover_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
			uint16_t sport, uint16_t dport, 
			uint32_t new_seq, uint32_t seq, uint32_t ack,
			size_t options_size, const uint8_t *options,
			uint16_t peer_mss, uint8_t peer_ws, uint32_t flags)
{
	fprintf(stderr, "Application: SYN (recovery)\n");
	send_segment(internal_log, saddr, daddr, sport, dport, TH_SYN, new_seq,
			0, options_size, options, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, daddr, saddr, dport, sport, TH_SYN | TH_ACK,
			ack, new_seq + 1, options_size, options, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(daddr, saddr, dport, sport, seq + 1, ack + 1, peer_mss,
			peer_ws, (new_seq + 1) - (seq + 1), flags);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, saddr, daddr, sport, dport, TH_ACK,
			new_seq + 1, ack + 1, 0, NULL, 0, NULL);
	recv_segment(external_log, faddr, daddr, sport, dport, TH_ACK, seq + 1,
			ack + 1, 0, NULL, 0, NULL);
}

void cleanup_connection(uint32_t peer_address, uint32_t address,
			uint16_t peer_port, uint16_t port,
			uint32_t peer_ack, uint32_t ack,
			uint32_t delta)
{
	fprintf(stderr, "Application: update (remove state)\n");
	send_update(peer_address, address, peer_port, port, peer_ack, ack, 0,
			0, delta, TCPR_FINISHED);
}

void send_segment(FILE *log, uint32_t saddr, uint32_t daddr,
			uint16_t sport, uint16_t dport, uint8_t flags,
			uint32_t seq, uint32_t ack,
			size_t options_size, const uint8_t *options,
			size_t payload_size, const char *payload)
{
	uint8_t packet[SNAPLEN];
	struct ip *ip;
	struct tcphdr *tcp;
	size_t size = sizeof(*ip) + sizeof(*tcp) + options_size + payload_size;
    uint8_t *option_ptr = options;
    uint8_t digest[16];

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

    while (option_ptr < options + options_size && *option_ptr != TCPOPT_EOL)
        switch (*option_ptr) {
        case 19:
            compute_md5_checksum(ip, tcp, digest);
            memcpy(option_ptr+2, digest, 16);
        default:
            option_ptr += option_ptr[1];
            break;
        }

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
			size_t options_size, const uint8_t *options,
			size_t payload_size, const char *payload)
{
	uint8_t packet[SNAPLEN];
	struct ip *ip;
	struct tcphdr *tcp;
	ssize_t size;
    uint8_t *option_ptr = options;
    uint8_t digest[16];
    int i;

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

    while (option_ptr < options + options_size && *option_ptr != TCPOPT_EOL)
        switch (*option_ptr) {
        case 19:
            compute_md5_checksum(ip, tcp, digest);
            memcpy(option_ptr+2, digest, 16);
        default:
            option_ptr += option_ptr[1];
            break;
        }

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

void send_update(uint32_t peer_address, uint32_t address,
			uint16_t peer_port, uint16_t port,
			uint32_t peer_ack, uint32_t ack,
			uint16_t peer_mss, uint8_t peer_ws,
			uint32_t delta, uint32_t flags)
{
	struct update update;

	update.peer_address = htonl(peer_address);
	update.address = htonl(address);
	update.tcpr.peer_port = htons(peer_port);
	update.tcpr.port = htons(port);
	update.tcpr.peer_ack = htonl(peer_ack);
	update.tcpr.ack = htonl(ack);
	update.tcpr.peer_mss = htonl(peer_mss);
	update.tcpr.peer_ws = htonl(peer_ws);
	update.tcpr.delta = delta;
	update.tcpr.flags = flags;

	sendto(update_socket, &update, sizeof(update), 0,
		(struct sockaddr *)&filter_address, sizeof(filter_address));
}

void recv_update(uint32_t peer_address, uint32_t address,
			uint16_t peer_port, uint16_t port,
			uint32_t peer_ack, uint32_t ack,
			uint16_t peer_mss, uint8_t peer_ws,
			uint32_t delta, uint32_t flags)
{
	struct update update;
	ssize_t size;

	size = read(update_socket, &update, sizeof(update));

	expect(size, sizeof(update), "Size of update");
	expect(ntohl(update.peer_address), peer_address, "Update peer address");
	expect(ntohl(update.address), address, "Update address");
	expect(ntohs(update.tcpr.peer_port), peer_port, "Update peer port");
	expect(ntohs(update.tcpr.port), port, "Update port");
	expect(ntohl(update.tcpr.peer_ack), peer_ack,
		"Update peer acknowledgment");
	if (flags & TCPR_HAVE_PEER_MSS)
		expect(update.tcpr.peer_mss, peer_mss,
			"Update peer maximum segment size");
	if (flags & TCPR_HAVE_PEER_WS)
		expect(update.tcpr.peer_ws, peer_ws,
			"Update peer window scaling");
	expect(ntohl(update.tcpr.ack), ack, "Update acknowledgment");
	expect(update.tcpr.delta, delta, "Update delta");
	expect(update.tcpr.flags, flags, "Update flags");
}
