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

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

extern FILE *external_log;
extern FILE *internal_log;
extern int tun;

extern uint8_t peer_ws;
extern uint16_t peer_mss;
extern size_t test_options_size;
extern char* test_options; 

int open_tun(char *device);
FILE *open_log(char *file);

void log_packet(FILE *f, const char *packet, size_t size);

void expect(uint32_t actual, uint32_t expected, const char *s);

uint32_t shorten(uint32_t n);

uint32_t checksum(uint16_t *data, size_t size);

void compute_ip_checksum(struct ip *ip);
void compute_tcp_checksum(struct ip *ip, struct tcphdr *tcp);
void compute_udp_checksum(struct ip *ip, struct udphdr *udp);

void send_segment(FILE *log, uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport, uint8_t flags,
				uint32_t seq, uint32_t ack,
				size_t options_size, const char *options,
				size_t payload_size, const char *payload);

void recv_segment(FILE *log, uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport, uint8_t flags,
				uint32_t seq, uint32_t ack,
				size_t options_size, const char *options,
				size_t payload_size, const char *payload);

void setup_update_connection(void);
void send_update(uint32_t peer_address, uint32_t address,
				uint16_t peer_port, uint16_t port,
				uint32_t peer_ack, uint32_t ack,
				uint16_t peer_mss, uint8_t peer_ws,
				uint32_t delta, uint32_t flags);

void recv_update(uint32_t peer_address, uint32_t address,
				uint16_t peer_port, uint16_t port,
				uint32_t peer_ack, uint32_t ack,
				uint16_t peer_mss, uint8_t peer_ws,
				uint32_t delta, uint32_t flags);

void setup_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
						uint16_t sport, uint16_t dport, 
						uint32_t start_seq, uint32_t start_ack,
						size_t options_size, const char *options,
						uint16_t peer_mss, uint8_t peer_ws);


void teardown_connection(uint32_t peer_address, uint32_t address,
							uint16_t peer_port, uint16_t port,
							uint32_t peer_ack, uint32_t ack,
							uint32_t delta);


void setup_test(char *device, char *log_name);

void cleanup_test();

void recover_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
				uint16_t sport, uint16_t dport, 
				uint32_t new_seq, uint32_t seq, uint32_t ack,
				size_t options_size, const char *options,
				uint16_t peer_mss, uint8_t peer_ws, uint32_t flags);
