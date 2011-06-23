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
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	struct tcpr_connection tcpr;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Debug connection state.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b HOST[:PORT]  "
		"Debug application bound to HOST at PORT.\n");
	fprintf(stderr, "  -c HOST[:PORT]  "
		"Debug application connected to HOST at PORT.\n");
	fprintf(stderr, "  -?              "
		"Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void parse_address(char *address, const char **host, const char **port)
{
	char *tmp = strrchr(address, ':');
	if (tmp) {
		*tmp++ = '\0';
		*port = *tmp ? tmp : NULL;
	} else {
		*port = NULL;
	}
	*host = *address ? address : NULL;
}

static void handle_options(struct state *s, int argc, char **argv)
{
	int o;

	s->bind_host = NULL;
	s->bind_port = NULL;
	s->connect_host = NULL;
	s->connect_port = NULL;

	while ((o = getopt(argc, argv, "b:c:p?")) != -1)
		switch (o) {
		case 'b':
			parse_address(optarg, &s->bind_host, &s->bind_port);
			break;
		case 'c':
			parse_address(optarg, &s->connect_host, &s->connect_port);
			break;
		default:
			print_help_and_exit(argv[0]);
		}

	if (!s->bind_host)
		s->bind_host = "127.0.0.2";
	if (!s->bind_port)
		s->bind_port = "8888";
	if (!s->connect_host)
		s->connect_host = "127.0.0.1";
	if (!s->connect_port)
		s->connect_port = "9999";
};

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

	err = getaddrinfo(s->bind_host, s->bind_port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving bind address: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	err = getaddrinfo(s->connect_host, s->connect_port, &hints, &peer_ai);
	if (err) {
		fprintf(stderr, "Resolving peer address: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	if (tcpr_setup_connection(&s->tcpr, (struct sockaddr_in *)peer_ai->ai_addr, ((struct sockaddr_in *)ai->ai_addr)->sin_port, 0) < 0) {
		perror("Error setting up TCPR");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(ai);
	freeaddrinfo(peer_ai);
}

static void print_state(struct state *s)
{
	fprintf(stderr, "Saved ACK: %"PRIu32"\n", ntohl(s->tcpr.state->saved.ack));
	fprintf(stderr, "Saved peer ACK: %"PRIu32"\n", ntohl(s->tcpr.state->saved.safe));
	if (s->tcpr.state->saved.peer.mss)
		fprintf(stderr, "Peer MSS: %"PRIu16"\n", s->tcpr.state->saved.peer.mss);
	if (s->tcpr.state->saved.peer.ws)
		fprintf(stderr, "Peer WS: %"PRIu8"\n", s->tcpr.state->saved.peer.ws - 1);
	if (s->tcpr.state->saved.peer.sack_permitted)
		fprintf(stderr, "Peer SACK permitted.\n");
	fprintf(stderr, "Delta: %"PRIu32"\n", s->tcpr.state->delta);
	fprintf(stderr, "ACK: %"PRIu32"\n", ntohl(s->tcpr.state->ack));
	if (s->tcpr.state->have_fin)
		fprintf(stderr, "FIN: %"PRIu32"\n", ntohl(s->tcpr.state->fin));
	fprintf(stderr, "SEQ: %"PRIu32"\n", ntohl(s->tcpr.state->seq));
	fprintf(stderr, "WIN: %"PRIu16"\n", ntohs(s->tcpr.state->win));
	if (s->tcpr.state->peer.have_ack)
		fprintf(stderr, "Peer ACK: %"PRIu32"\n", ntohl(s->tcpr.state->peer.ack));
	if (s->tcpr.state->peer.have_fin)
		fprintf(stderr, "Peer FIN: %"PRIu32"\n", ntohl(s->tcpr.state->peer.fin));
	fprintf(stderr, "Peer WIN: %"PRIu16"\n", ntohs(s->tcpr.state->peer.win));
	if (s->tcpr.state->saved.done_reading)
		fprintf(stderr, "Done reading.\n");
	if (s->tcpr.state->saved.done_writing)
		fprintf(stderr, "Done writing.\n");
	if (s->tcpr.state->done)
		fprintf(stderr, "Done.\n");
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
