#ifndef TCPR_APPLICATION_H
#define TCPR_APPLICATION_H

#include <tcpr/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

enum tcpr_connection_flags {
	TCPR_CONNECTION_CREATE = 0x1,
	TCPR_CONNECTION_FILTER = 0x2,
};

struct tcpr_connection {
	int control_socket;
	struct sockaddr_un control_address;
	struct tcpr *state;
};

int tcpr_setup_connection(struct tcpr_connection *c, struct sockaddr_in *peer,
			  uint16_t port, int flags);
void tcpr_destroy_connection(struct sockaddr_in *peer, uint16_t port);
void tcpr_teardown_connection(struct tcpr_connection *c);

size_t tcpr_safe(struct tcpr_connection *c);
void tcpr_advance(struct tcpr_connection *c, size_t bytes);
int tcpr_consume(struct tcpr_connection *c, size_t bytes);
int tcpr_done_reading(struct tcpr_connection *c);
void tcpr_done_writing(struct tcpr_connection *c);

#endif
