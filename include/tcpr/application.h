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

size_t tcpr_output_bytes(struct tcpr_connection *c);
size_t tcpr_input_bytes(struct tcpr_connection *c);
void tcpr_checkpoint_output(struct tcpr_connection *c, size_t bytes);
int tcpr_checkpoint_input(struct tcpr_connection *c, size_t bytes);
void tcpr_shutdown_output(struct tcpr_connection *c);
int tcpr_shutdown_input(struct tcpr_connection *c);
int tcpr_close(struct tcpr_connection *c);
void tcpr_wait(struct tcpr_connection *c);

#endif
