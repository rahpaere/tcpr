#ifndef TCPR_MODULE_H
#define TCPR_MODULE_H

#define TCPR_MAJOR 251

struct tcpr_connection {
	uint32_t address;
	uint32_t peer_address;
	uint16_t port;
	uint16_t peer_port;
};

#define TCPR_ATTACH _IOW(TCPR_MAJOR, 1, struct tcpr_connection *)
#define TCPR_GET _IOR(TCPR_MAJOR, 2, struct tcpr *)
#define TCPR_ACK _IOW(TCPR_MAJOR, 3, unsigned long)
#define TCPR_DONE_READING _IO(TCPR_MAJOR, 4)
#define TCPR_DONE_WRITING _IO(TCPR_MAJOR, 5)
#define TCPR_CLOSE _IO(TCPR_MAJOR, 6)
#define TCPR_KILL _IO(TCPR_MAJOR, 7)
#define TCPR_WAIT _IO(TCPR_MAJOR, 8)
#define TCPR_DONE _IO(TCPR_MAJOR, 9)

#endif
