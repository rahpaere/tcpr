#include <tcpr/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int connect_to_tcpr(struct sockaddr_in *addr)
{
	int s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		close(s);
		return -1;
	}

	return s;
}

static int put_tcpr_state(struct tcpr_ip4 *state)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = state->peer_address;
	addr.sin_port = state->tcpr.hard.peer.port;

	s = connect_to_tcpr(&addr);
	if (s < 0)
		return -1;

	if (send(s, &state, sizeof(state), 0) < 0)
		return -1;

	return close(s);
}

int main(int argc, char **argv)
{
	struct tcpr_ip4 state;

	(void)argc;
	(void)argv;

	while (fread(&state, sizeof(state), 1, stdin)) {
		if (put_tcpr_state(&state) < 0)
			perror("Sending TCPR state");
	}

	return EXIT_SUCCESS;
}
