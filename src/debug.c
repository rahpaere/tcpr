#include <tcpr/application.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

struct state {
	const char *peer_host;
	const char *peer_port;
	const char *port;
	struct tcpr_connection tcpr;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Print a human-readable representation of TCPR "
		"connection state.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -a PORT  The application is bound to PORT.\n");
	fprintf(stderr, "  -h HOST  The peer is bound to HOST.\n");
	fprintf(stderr, "  -p PORT  The peer is bound to PORT.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(struct state *s, int argc, char **argv)
{
	int o;

	s->peer_host = "127.0.0.1";
	s->peer_port = "9999";
	s->port = "8888";

	while ((o = getopt(argc, argv, "h:p:P?")) != -1)
		switch (o) {
		case 'h':
			s->peer_host = optarg;
			break;
		case 'p':
			s->peer_port = optarg;
			break;
		case 'P':
			s->port = optarg;
			break;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup_state(struct state *s)
{
	int err;
	struct addrinfo *ai;
	struct addrinfo *peer_ai;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(s->peer_host, s->peer_port, &hints, &peer_ai);
	if (err) {
		fprintf(stderr, "Resolving peer: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	err = getaddrinfo(NULL, s->port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving port: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	if (tcpr_setup_connection
	    (&s->tcpr, (struct sockaddr_in *)peer_ai->ai_addr,
	     ((struct sockaddr_in *)ai->ai_addr)->sin_port, 0) < 0) {
		perror("Opening state");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(ai);
	freeaddrinfo(peer_ai);
}

static void print_state(struct state *s)
{
	printf("Saved ACK: %" PRIu32 "\n", ntohl(s->tcpr.state->saved.ack));
	printf("Saved peer ACK: %" PRIu32 "\n",
	       ntohl(s->tcpr.state->saved.safe));
	if (s->tcpr.state->saved.peer.mss)
		printf("Peer MSS: %" PRIu16 "\n",
		       s->tcpr.state->saved.peer.mss);
	if (s->tcpr.state->saved.peer.ws)
		printf("Peer WS: %" PRIu8 "\n",
		       s->tcpr.state->saved.peer.ws - 1);
	if (s->tcpr.state->saved.peer.sack_permitted)
		printf("Peer SACK permitted.\n");
	printf("Delta: %" PRIu32 "\n", s->tcpr.state->delta);
	printf("ACK: %" PRIu32 "\n", ntohl(s->tcpr.state->ack));
	if (s->tcpr.state->have_fin)
		printf("FIN: %" PRIu32 "\n", ntohl(s->tcpr.state->fin));
	printf("SEQ: %" PRIu32 "\n", ntohl(s->tcpr.state->seq));
	printf("WIN: %" PRIu16 "\n", ntohs(s->tcpr.state->win));
	if (s->tcpr.state->peer.have_ack)
		printf("Peer ACK: %" PRIu32 "\n",
		       ntohl(s->tcpr.state->peer.ack));
	if (s->tcpr.state->peer.have_fin)
		printf("Peer FIN: %" PRIu32 "\n",
		       ntohl(s->tcpr.state->peer.fin));
	printf("Peer WIN: %" PRIu16 "\n", ntohs(s->tcpr.state->peer.win));
	if (s->tcpr.state->saved.done_reading)
		printf("Done reading.\n");
	if (s->tcpr.state->saved.done_writing)
		printf("Done writing.\n");
	if (s->tcpr.state->done)
		printf("Done.\n");
}

static void teardown_state(struct state *s)
{
	tcpr_teardown_connection(&s->tcpr);
}

int main(int argc, char **argv)
{
	struct state s;

	handle_options(&s, argc, argv);

	setup_state(&s);
	print_state(&s);
	teardown_state(&s);

	return EXIT_SUCCESS;
}
