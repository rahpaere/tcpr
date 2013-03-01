#include <tcpr/types.h>
#include <tcpr/util.h>

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

int main(int argc, char **argv)
{
	int err;
	int s;
	struct sockaddr_in addr;
	struct sockaddr_in srcaddr;
	struct tcpr_ip4 state;

	if (argc != 2 && argc != 4) {
		fprintf(stderr, "Usage: %s SRCPORT [HOST PORT]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	err = resolve_address(&srcaddr, NULL, argv[1]);
	if (err) {
		fprintf(stderr, "%s: %s\n", argv[1], gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	if (argc == 4) {
		err = resolve_address(&addr, argv[2], argv[3]);
		if (err) {
			fprintf(stderr, "%s:%s: %s\n", argv[2], argv[3],
				gai_strerror(err));
			exit(EXIT_FAILURE);
		}
	} else {
		memset(&addr, 0, sizeof(addr));
	}

	s = connect_to_tcpr();
	if (s < 0) {
		fprintf(stderr, "Could not connect to TCPR.\n");
		exit(EXIT_FAILURE);
	}

	if (get_tcpr_state(&state, s, &addr, &srcaddr) < 0) {
		perror("Getting state");
		exit(EXIT_FAILURE);
	}

	fwrite(&state, sizeof(state), 1, stdout);
	return EXIT_SUCCESS;
}
