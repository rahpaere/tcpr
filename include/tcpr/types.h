#ifndef TCPR_TYPES_H
#define TCPR_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct tcpr_saved {
	uint16_t internal_port;
	uint16_t external_port;
	uint32_t ack;
	uint32_t safe;
	struct {
		uint16_t port;
		uint16_t mss;
		uint8_t ws;
		uint8_t sack_permitted;
	} peer;
	uint8_t done_reading;
	uint8_t done_writing;
};

struct tcpr {
	struct tcpr_saved saved;
	uint32_t delta;
	uint32_t ack;
	uint32_t fin;
	uint32_t seq;
	uint16_t win;
	struct {
		uint32_t ack;
		uint32_t fin;
		uint16_t win;
		uint8_t have_fin;
		uint8_t have_ack;
	} peer;
	uint8_t have_fin;
	uint8_t done;
};

#endif
