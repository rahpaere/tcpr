#include <tcpr/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"

int main(int argc, char **argv)
{
	int bytes = 0;
	struct tcpr_ip4 state;
	uint32_t max;

	if (argc > 1)
		bytes = atoi(argv[1]);

	while (fread(&state, sizeof(state), 1, stdin)) {
		max = ntohl(state.tcpr.hard.ack) - ntohl(state.tcpr.ack);
		if (!bytes || bytes > max)
			state.tcpr.hard.ack = state.tcpr.ack;
		else
			state.tcpr.hard.ack =
			    htonl(ntohl(state.tcpr.hard.ack) + bytes);
		fwrite(&state, sizeof(state), 1, stdout);
	}

	return EXIT_SUCCESS;
}
