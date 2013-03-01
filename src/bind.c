#include <tcpr/types.h>
#include <tcpr/util.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char **argv)
{
	int err;
	struct sockaddr_in addr;
	struct tcpr_ip4 state;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s HOST PORT\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	err = resolve_address(&addr, argv[1], argv[2]);
	if (err) {
		fprintf(stderr, "%s:%s: %s\n", argv[1], argv[2],
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	while (fread(&state, sizeof(state), 1, stdin)) {
		state.address = addr.sin_addr.s_addr;
		state.tcpr.port = addr.sin_port;
		fwrite(&state, sizeof(state), 1, stdout);
	}

	return EXIT_SUCCESS;
}
