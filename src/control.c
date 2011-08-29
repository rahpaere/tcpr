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
	const char *save_file;
	const char *recovery_file;
	int input_bytes;
	int output_bytes;
	int wait;
	int destroy;
	struct sockaddr_in peer_address;
	struct sockaddr_in address;
	struct tcpr_connection tcpr;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Manipulate and display TCPR connection state.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -a PORT  The application is bound to PORT.\n");
	fprintf(stderr, "  -h HOST  The peer is bound to HOST.\n");
	fprintf(stderr, "  -p PORT  The peer is bound to PORT.\n");
	fprintf(stderr, "  -S FILE  Save the connection state into FILE.\n");
	fprintf(stderr, "  -R FILE  Recover the connection state from FILE.\n");
	fprintf(stderr, "  -I NUM   Acknowledge NUM bytes of input;\n"
		"           if NUM is negative, shut down input.\n");
	fprintf(stderr, "  -O NUM   Checkpoint NUM bytes of output;\n"
		"           if NUM is negative, shut down output.\n");
	fprintf(stderr, "  -W       Wait until the connection is done.\n");
	fprintf(stderr, "  -D       Destroy the connection state.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(struct state *s, int argc, char **argv)
{
	int o;

	s->peer_host = "127.0.0.1";
	s->peer_port = "9999";
	s->port = "8888";
	s->save_file = NULL;
	s->recovery_file = NULL;
	s->input_bytes = 0;
	s->output_bytes = 0;
	s->wait = 0;
	s->destroy = 0;

	while ((o = getopt(argc, argv, "a:h:p:S:R:I:O:WD?")) != -1)
		switch (o) {
		case 'a':
			s->port = optarg;
			break;
		case 'h':
			s->peer_host = optarg;
			break;
		case 'p':
			s->peer_port = optarg;
			break;
		case 'S':
			s->save_file = optarg;
			break;
		case 'R':
			s->recovery_file = optarg;
			break;
		case 'I':
			s->input_bytes = atoi(optarg);
			break;
		case 'O':
			s->output_bytes = atoi(optarg);
			break;
		case 'W':
			s->wait = 1;
			break;
		case 'D':
			s->destroy = 1;
			break;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup_state(struct state *s)
{
	int err;
	int flags = 0;
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
	memcpy(&s->peer_address, peer_ai->ai_addr, sizeof(s->peer_address));
	freeaddrinfo(peer_ai);

	err = getaddrinfo(NULL, s->port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving port: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	memcpy(&s->address, ai->ai_addr, sizeof(s->address));
	freeaddrinfo(ai);

	if (s->recovery_file)
		flags |= TCPR_CONNECTION_CREATE;
	if (tcpr_setup_connection
	    (&s->tcpr, &s->peer_address, s->address.sin_port, flags) < 0) {
		perror("Opening state");
		exit(EXIT_FAILURE);
	}
}

static void update_state(struct state *s)
{
	int fd;

	if (s->recovery_file) {
		fd = open(s->recovery_file, O_RDONLY);
		if (fd < 0) {
			perror("Opening recovery file");
			exit(EXIT_FAILURE);
		}
		if (read
		    (fd, &s->tcpr.state->saved,
		     sizeof(s->tcpr.state->saved)) !=
		    sizeof(s->tcpr.state->saved)) {
			perror("Recovering");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing recovery file");
			exit(EXIT_FAILURE);
		}
	}

	if (s->output_bytes < 0)
		tcpr_done_writing(&s->tcpr);
	else if (s->output_bytes > 0)
		tcpr_advance(&s->tcpr, s->output_bytes);
	if (s->input_bytes < 0)
		tcpr_done_reading(&s->tcpr);
	else if (s->input_bytes > 0)
		tcpr_consume(&s->tcpr, s->input_bytes);
}

static void wait_until_done(struct state *s)
{
	while (!s->tcpr.state->done)
		sleep(1);
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
		printf("The application is done reading.\n");
	if (s->tcpr.state->saved.done_writing)
		printf("The application is done writing.\n");
	if (s->tcpr.state->done)
		printf("The connection is finished.\n");
}

static void teardown_state(struct state *s)
{
	int fd;

	if (s->save_file) {
		fd = creat(s->save_file, 0600);
		if (fd < 0) {
			perror("Opening save file");
			exit(EXIT_FAILURE);
		}
		if (write
		    (fd, &s->tcpr.state->saved,
		     sizeof(s->tcpr.state->saved)) !=
		    sizeof(s->tcpr.state->saved)) {
			perror("Saving");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing save file");
			exit(EXIT_FAILURE);
		}
	}

	tcpr_teardown_connection(&s->tcpr);
	if (s->destroy)
		tcpr_destroy_connection(&s->peer_address, s->address.sin_port);
}

int main(int argc, char **argv)
{
	struct state s;

	handle_options(&s, argc, argv);

	setup_state(&s);
	update_state(&s);
	if (s.wait)
		wait_until_done(&s);
	print_state(&s);
	teardown_state(&s);

	return EXIT_SUCCESS;
}
