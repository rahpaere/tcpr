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

#include "util.h"

int main(int argc, char **argv)
{
	int err;
	int s;
	struct sockaddr_in addr;
	struct sockaddr_in srcaddr;
	struct tcpr_ip4 state;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s HOST PORT SRCPORT\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	err = resolve_address(&addr, argv[1], argv[1]);
	if (err) {
		fprintf(stderr, "%s:%s: %s\n", argv[1], argv[2], gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	err = resolve_address(&srcaddr, NULL, argv[3]);
	if (err) {
		fprintf(stderr, "%s: %s\n", argv[3], gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	s = connect_to_tcpr(&addr);
	if (s < 0) {
		perror("Connecting");
		exit(EXIT_FAILURE);
	}

	if (get_tcpr_state(&state, s, &addr, &srcaddr) < 0) {
		perror("Getting state");
		exit(EXIT_FAILURE);
	}

	fwrite(&state, sizeof(state), 1, stdout);
	return EXIT_SUCCESS;
}
