#include <tcpr/application.h>

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char *peer_host = "127.0.0.1";
static const char *peer_port = "9999";
static const char *port = "8888";
static const char *save_file;
static const char *recovery_file;
static int input_bytes;
static int output_bytes;
static int kill;
static int wait;
static int destroy;
static struct sockaddr_in peer_address;
static struct sockaddr_in address;
static struct tcpr_connection tcpr;

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
	fprintf(stderr, "  -I NUM   Acknowledge NUM bytes of input.\n");
	fprintf(stderr, "  -I all   Acknowledge all outstanding input.\n");
	fprintf(stderr, "  -I done  Shut down input.\n");
	fprintf(stderr, "  -O NUM   Checkpoint NUM bytes of output.\n");
	fprintf(stderr, "  -O all   Checkpoint all outstanding output.\n");
	fprintf(stderr, "  -O done  Shut down output.\n");
	fprintf(stderr, "  -K       Kill the application's connection.\n");
	fprintf(stderr, "  -W       Wait until the connection is done.\n");
	fprintf(stderr, "  -D       Destroy the connection state.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "a:h:p:S:R:I:O:KWD?")) {
		case 'a':
			port = optarg;
			break;
		case 'h':
			peer_host = optarg;
			break;
		case 'p':
			peer_port = optarg;
			break;
		case 'S':
			save_file = optarg;
			break;
		case 'R':
			recovery_file = optarg;
			break;
		case 'I':
			if (!strcmp(optarg, "done"))
				input_bytes = -1;
			else if (!strcmp(optarg, "all"))
				input_bytes = INT_MAX;
			else
				input_bytes = atoi(optarg);
			break;
		case 'O':
			if (!strcmp(optarg, "done"))
				output_bytes = -1;
			else if (!strcmp(optarg, "all"))
				output_bytes = INT_MAX;
			else
				output_bytes = atoi(optarg);
			break;
		case 'K':
			kill = 1;
			break;
		case 'W':
			wait = 1;
			break;
		case 'D':
			destroy = 1;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup(void)
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

	err = getaddrinfo(peer_host, peer_port, &hints, &peer_ai);
	if (err) {
		fprintf(stderr, "Resolving peer: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	memcpy(&peer_address, peer_ai->ai_addr, sizeof(peer_address));
	freeaddrinfo(peer_ai);

	err = getaddrinfo(NULL, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving port: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	memcpy(&address, ai->ai_addr, sizeof(address));
	freeaddrinfo(ai);

	if (recovery_file)
		flags |= TCPR_CONNECTION_CREATE;
	if (tcpr_setup_connection(&tcpr, peer_address.sin_addr.s_addr,
					peer_address.sin_port,
					address.sin_port, flags) < 0) {
		perror("Opening state");
		exit(EXIT_FAILURE);
	}
}

static void update(void)
{
	int fd;
	size_t bytes;

	if (recovery_file) {
		fd = open(recovery_file, O_RDONLY);
		if (fd < 0) {
			perror("Opening recovery file");
			exit(EXIT_FAILURE);
		}
		if (read(fd, &tcpr.state->saved, sizeof(tcpr.state->saved))
					!= sizeof(tcpr.state->saved)) {
			perror("Recovering");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing recovery file");
			exit(EXIT_FAILURE);
		}
	}

	if (output_bytes < 0) {
		tcpr_shutdown_output(&tcpr);
	} else if (output_bytes > 0) {
		bytes = tcpr_output_bytes(&tcpr);
		if ((size_t)output_bytes < bytes)
			bytes = output_bytes;
		tcpr_checkpoint_output(&tcpr, bytes);
	}

	if (input_bytes < 0) {
		tcpr_shutdown_input(&tcpr);
	} else if (input_bytes > 0) {
		bytes = tcpr_input_bytes(&tcpr);
		if ((size_t)input_bytes < bytes)
			bytes = input_bytes;
		tcpr_checkpoint_input(&tcpr, bytes);
	}

	if (kill)
		tcpr_kill(&tcpr);
}

static void print(void)
{
	struct tcpr *t = tcpr.state;

	if (t->saved.external_port)
		printf("%12" PRIu16 "  External port\n",
			ntohs(t->saved.external_port));
	if (t->saved.internal_port)
		printf("%12" PRIu16 "  Internal port\n",
			ntohs(t->saved.internal_port));
	if (t->saved.peer.port)
		printf("%12" PRIu16 "  Peer port\n",
			ntohs(t->saved.peer.port));
	printf("%12zd  Outstanding input\n", tcpr_input_bytes(&tcpr));
	printf("%12zd  Outstanding output\n", tcpr_output_bytes(&tcpr));
	printf("%12" PRIu32 "  Checkpointed ACK\n", ntohl(t->saved.ack));
	printf("%12" PRIu32 "  Checkpointed peer ACK\n", ntohl(t->saved.safe));
	if (t->saved.peer.mss)
		printf("%12" PRIu16 "  Peer MSS\n", t->saved.peer.mss);
	if (t->saved.peer.ws)
		printf("%12" PRIu8 "  Peer WS\n", t->saved.peer.ws - 1);
	if (t->saved.peer.sack_permitted)
		printf("              Peer SACK permitted\n");
	if (t->saved.done_reading)
		printf("              Done reading\n");
	if (t->saved.done_writing)
		printf("              Done writing\n");
	else if (t->have_fin)
		printf("              Crashed\n");
	if (t->done)
		printf("              Closed\n");
	printf("%12" PRIu32 "  Delta\n", t->delta);
	printf("%12" PRIu32 "  ACK\n", ntohl(t->ack));
	if (t->have_fin && t->saved.done_writing)
		printf("%12" PRIu32 "  FIN\n", ntohl(t->fin));
	printf("%12" PRIu32 "  SEQ\n", ntohl(t->seq));
	printf("%12" PRIu16 "  WIN\n", ntohs(t->win));
	if (t->peer.have_ack)
		printf("%12" PRIu32 "  Peer ACK\n", ntohl(t->peer.ack));
	if (t->peer.have_fin)
		printf("%12" PRIu32 "  Peer FIN\n", ntohl(t->peer.fin));
	printf("%12" PRIu16 "  Peer WIN\n", ntohs(t->peer.win));
}

static void teardown(void)
{
	int fd;

	if (save_file) {
		fd = creat(save_file, 0600);
		if (fd < 0) {
			perror("Opening save file");
			exit(EXIT_FAILURE);
		}
		if (write(fd, &tcpr.state->saved, sizeof(tcpr.state->saved))
					!= sizeof(tcpr.state->saved)) {
			perror("Saving");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing save file");
			exit(EXIT_FAILURE);
		}
	}

	tcpr_teardown_connection(&tcpr);
	if (destroy)
		tcpr_destroy_connection(peer_address.sin_addr.s_addr,
					peer_address.sin_port,
					address.sin_port);
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup();
	update();
	if (wait)
		tcpr_wait(&tcpr);
	print();
	teardown();
	return EXIT_SUCCESS;
}
