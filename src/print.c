#include <tcpr/types.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void print_tcpr_state(struct tcpr_ip4 *state)
{
	char addrstr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &state->peer_address, addrstr, sizeof(addrstr));
	printf("%12s  Peer address\n", addrstr);

	printf("%12" PRIu16 "  Peer port\n", ntohs(state->tcpr.hard.peer.port));

	printf("%12" PRIu16 "  Port\n", ntohs(state->tcpr.hard.port));

	if (state->address) {
		inet_ntop(AF_INET, &state->address, addrstr, sizeof(addrstr));
		printf("%12s  Internal address\n", addrstr);
	}

	if (state->tcpr.port)
		printf("%12" PRIu16 "  Internal port\n", ntohs(state->tcpr.port));

	if (state->tcpr.hard.peer.mss)
		printf("%12" PRIu16 "  Peer MSS\n", state->tcpr.hard.peer.mss);
	if (state->tcpr.hard.peer.ws)
		printf("%12" PRIu8 "  Peer WS\n", state->tcpr.hard.peer.ws - 1);
	if (state->tcpr.hard.peer.sack_permitted)
		printf("%12s  Peer SACK permitted\n", "");

	if (state->tcpr.syn_sent)
		printf("%12s  SYN sent\n", "");

	if (state->tcpr.hard.done_reading)
		printf("%12s  Done reading\n", "");
	if (state->tcpr.hard.done_writing)
		printf("%12s  Done writing\n", "");
	if (state->tcpr.done)
		printf("%12s  Done\n", "");
	if (state->tcpr.failed)
		printf("%12s  Failed\n", "");

	printf("%12" PRIu32 "  Checkpointed ACK\n", ntohl(state->tcpr.hard.ack));
	printf("%12" PRIu32 "  Delta\n", state->tcpr.delta);
	printf("%12" PRIu32 "  ACK\n", ntohl(state->tcpr.ack));
	if (state->tcpr.have_fin)
		printf("%12" PRIu32 "  FIN\n", ntohl(state->tcpr.fin));
	printf("%12" PRIu32 "  SEQ\n", ntohl(state->tcpr.seq));
	printf("%12" PRIu16 "  WIN\n", ntohs(state->tcpr.win));

	if (state->tcpr.peer.have_ack)
		printf("%12" PRIu32 "  Peer ACK\n", ntohl(state->tcpr.peer.ack));

	if (state->tcpr.peer.have_fin)
		printf("%12" PRIu32 "  Peer FIN\n", ntohl(state->tcpr.peer.fin));
	printf("%12" PRIu16 "  Peer WIN\n", ntohs(state->tcpr.peer.win));
}

int main(int argc, char **argv)
{
	struct tcpr_ip4 state;
	int first = 1;

	(void)argc;
	(void)argv;

	while (fread(&state, sizeof(state), 1, stdin)) {
		if (first)
			first = 0;
		else
			putchar('\n');
		print_tcpr_state(&state);
	}

	return EXIT_SUCCESS;
}
