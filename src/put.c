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
	int s;
	struct tcpr_ip4 state;

	(void)argc;
	(void)argv;

	s = connect_to_tcpr();
	if (s < 0) {
		fprintf(stderr, "Could not connect to TCPR.\n");
		exit(EXIT_FAILURE);
	}

	while (fread(&state, sizeof(state), 1, stdin))
		if (send(s, &state, sizeof(state), 0) < 0) {
			perror("Sending TCPR state");
			exit(EXIT_FAILURE);
		}

	return EXIT_SUCCESS;
}
