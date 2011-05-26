#ifndef TCPR_APPLICATION_H
#define TCPR_APPLICATION_H

#include <tcpr/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

struct tcpr_connection {
	struct tcpr *state;
	struct sockaddr_un control_address;
	int control_socket;
};

int tcpr_setup_connection(struct tcpr_connection *c,
			  struct sockaddr_in *peer_address, uint16_t port);
void tcpr_teardown_connection(struct tcpr_connection *c);

int tcpr_consume(struct tcpr_connection *c, size_t bytes);
int tcpr_done_reading(struct tcpr_connection *c);
void tcpr_done_writing(struct tcpr_connection *c);

#endif
