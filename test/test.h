#ifndef TEST_H
#define TEST_H

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

#include "../md5util.h"

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

extern FILE *external_log;
extern FILE *internal_log;

extern uint16_t peer_mss;
extern uint8_t peer_ws;
extern uint8_t test_options[40]; 
extern size_t test_options_size;

void setup_test(const char *device, const char *log_name);
void cleanup_test(void);

void setup_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
			uint16_t sport, uint16_t dport, 
			uint32_t start_seq, uint32_t start_ack,
			size_t options_size, const uint8_t *options,
			uint16_t peer_mss, uint8_t peer_ws, char *password);
void recover_connection(uint32_t saddr, uint32_t daddr, uint32_t faddr,
			uint16_t sport, uint16_t dport, 
			uint32_t new_seq, uint32_t seq, uint32_t ack,
			size_t options_size, const uint8_t *options,
			uint16_t peer_mss, uint8_t peer_ws, uint32_t flags, char *password);
void cleanup_connection(uint32_t peer_address, uint32_t address,
			uint16_t peer_port, uint16_t port,
			uint32_t peer_ack, uint32_t ack,
			uint32_t delta);

void send_segment(FILE *log, uint32_t saddr, uint32_t daddr,
			uint16_t sport, uint16_t dport, uint8_t flags,
			uint32_t seq, uint32_t ack,
			size_t options_size, const uint8_t *options,
			size_t payload_size, const char *payload, char *password);
void recv_segment(FILE *log, uint32_t saddr, uint32_t daddr,
			uint16_t sport, uint16_t dport, uint8_t flags,
			uint32_t seq, uint32_t ack,
			size_t options_size, const uint8_t *options,
			size_t payload_size, const char *payload, char *password);

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

#endif
