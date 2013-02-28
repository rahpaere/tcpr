#include <tcpr/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	struct tcpr_ip4 state;

	if (argc > 1) {
		if (strchr(argv[1], 'r'))
			done_reading = 1;
		if (strchr(argv[1], 'w'))
			done_writing = 1;
	} else {
		done = 1;
	}

	while (fread(&state, sizeof(state), 1, stdin)) {
		state.tcpr.hard.done_reading = done_reading;
		state.tcpr.hard.done_writing = done_writing;
		state.tcpr.hard.done = done;
		fwrite(&state, sizeof(state), 1, stdout);
	}

	return EXIT_SUCCESS;
}
