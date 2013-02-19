#ifndef TCPR_TYPES_H
#define TCPR_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct tcpr_hard {
	uint16_t port;
	struct {
		uint16_t port;
		uint16_t mss;
		uint8_t ws;
		uint8_t sack_permitted;
	} peer;
	uint32_t ack;
	uint8_t done_reading;
	uint8_t done_writing;
};

struct tcpr {
	struct tcpr_hard hard;
	uint32_t delta;
	uint32_t ack;
	uint32_t fin;
	uint32_t seq;
	uint16_t win;
	uint16_t port;
	struct {
		uint32_t ack;
		uint32_t fin;
		uint16_t win;
		uint8_t have_fin;
		uint8_t have_ack;
	} peer;
	uint8_t have_fin;
	uint8_t done;
	uint8_t failed;
	uint8_t syn_sent;
};

struct tcpr_ip4 {
	uint32_t address;
	uint32_t peer_address;
	uint32_t hard_address;
	struct tcpr tcpr;
};

#endif
