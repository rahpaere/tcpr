#ifndef TCPR_MODULE_H
#define TCPR_MODULE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct tcpr_connection {
	uint32_t address;
	uint32_t peer_address;
	uint16_t port;
	uint16_t peer_port;
};

#define TCPR_ATTACH _IOW('t', 0x90, struct tcpr_connection)
#define TCPR_GET _IOR('t', 0x91, struct tcpr)
#define TCPR_ACK _IOW('t', 0x92, unsigned long)
#define TCPR_DONE_READING _IO('t', 0x93)
#define TCPR_DONE_WRITING _IO('t', 0x94)
#define TCPR_CLOSE _IO('t', 0x95)
#define TCPR_KILL _IO('t', 0x96)
#define TCPR_WAIT _IO('t', 0x97)
#define TCPR_DONE _IO('t', 0x98)

#endif
