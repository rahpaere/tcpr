#include <tcpr/types.h>
#include <tcpr/module.h>

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static const char *peer_host = "127.0.0.1";
static const char *peer_port = "9999";
static const char *host = "127.0.0.1";
static const char *port = "8888";
static const char *save_file;
static const char *recovery_file;
static int input_bytes;
static int output_bytes;
static int kill;
static int wait;
static int done;
static struct sockaddr_in peer_address;
static struct sockaddr_in address;
static struct tcpr_connection tcpr_connection;
static struct tcpr tcpr;
static int tcprfd;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Manipulate and display TCPR connection state.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h HOST  The application is bound to HOST.\n");
	fprintf(stderr, "  -p PORT  The application is bound to PORT.\n");
	fprintf(stderr, "  -H HOST  The peer is bound to HOST.\n");
	fprintf(stderr, "  -P PORT  The peer is bound to PORT.\n");
	fprintf(stderr, "  -S FILE  Save the connection state into FILE.\n");
	fprintf(stderr, "  -R FILE  Recover the connection state from FILE.\n");
	fprintf(stderr, "  -I NUM   Acknowledge NUM bytes of input.\n");
	fprintf(stderr, "  -I done  Shut down input.\n");
	fprintf(stderr, "  -O done  Shut down output.\n");
	fprintf(stderr, "  -K       Kill the application's connection.\n");
	fprintf(stderr, "  -W       Wait until the connection is done.\n");
	fprintf(stderr, "  -D       Mark the connection done.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "h:p:H:P:S:R:I:O:KWD?")) {
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'H':
			peer_host = optarg;
			break;
		case 'P':
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
			else
				input_bytes = atoi(optarg);
			break;
		case 'O':
			if (!strcmp(optarg, "done"))
				output_bytes = -1;
			break;
		case 'K':
			kill = 1;
			break;
		case 'W':
			wait = 1;
			break;
		case 'D':
			done = 1;
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

	err = getaddrinfo(host, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving port: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	memcpy(&address, ai->ai_addr, sizeof(address));
	freeaddrinfo(ai);

	tcprfd = open("/dev/tcpr", O_RDWR);
	if (tcprfd < 0) {
		perror("Opening TCPR handle");
		exit(EXIT_FAILURE);
	}

	tcpr_connection.address = address.sin_addr.s_addr;
	tcpr_connection.peer_address = peer_address.sin_addr.s_addr;
	tcpr_connection.port = address.sin_port;
	tcpr_connection.peer_port = peer_address.sin_port;
	if (ioctl(tcprfd, TCPR_ATTACH, &tcpr_connection) < 0) {
		perror("Attaching TCPR connection");
		exit(EXIT_FAILURE);
	}
	if (ioctl(tcprfd, TCPR_GET, &tcpr) < 0) {
		perror("Getting TCPR state");
		exit(EXIT_FAILURE);
	}
}

static void update(void)
{
	int fd;

	if (recovery_file) {
		fd = open(recovery_file, O_RDONLY);
		if (fd < 0) {
			perror("Opening recovery file");
			exit(EXIT_FAILURE);
		}
		if (read(fd, &tcpr.saved, sizeof(tcpr.saved)) != sizeof(tcpr.saved)) {
			perror("Recovering");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing recovery file");
			exit(EXIT_FAILURE);
		}
	}

	if (output_bytes < 0 && ioctl(tcprfd, TCPR_DONE_WRITING) < 0) {
		perror("Shutting down writing");
		exit(EXIT_FAILURE);
	}

	if (input_bytes < 0) {
		if (ioctl(tcprfd, TCPR_DONE_READING) < 0) {
			perror("Shutting down reading");
			exit(EXIT_FAILURE);
		}
	} else if (input_bytes > 0) {
		if (ioctl(tcprfd, TCPR_ACK, input_bytes) < 0) {
			perror("Acknowledging input");
			exit(EXIT_FAILURE);
		}
	}

	if (kill && ioctl(tcprfd, TCPR_KILL) < 0) {
		perror("Killing");
		exit(EXIT_FAILURE);
	}
}

static void print(void)
{
	if (ioctl(tcprfd, TCPR_GET, &tcpr) < 0) {
		perror("Getting TCPR state");
		exit(EXIT_FAILURE);
	}
	if (tcpr.saved.external_port)
		printf("%12" PRIu16 "  External port\n",
			ntohs(tcpr.saved.external_port));
	if (tcpr.saved.internal_port)
		printf("%12" PRIu16 "  Internal port\n",
			ntohs(tcpr.saved.internal_port));
	if (tcpr.saved.peer.port)
		printf("%12" PRIu16 "  Peer port\n",
			ntohs(tcpr.saved.peer.port));
	printf("%12" PRIu32 "  Checkpointed ACK\n", ntohl(tcpr.saved.ack));
	printf("%12" PRIu32 "  Checkpointed peer ACK\n", ntohl(tcpr.saved.safe));
	if (tcpr.saved.peer.mss)
		printf("%12" PRIu16 "  Peer MSS\n", tcpr.saved.peer.mss);
	if (tcpr.saved.peer.ws)
		printf("%12" PRIu8 "  Peer WS\n", tcpr.saved.peer.ws - 1);
	if (tcpr.saved.peer.sack_permitted)
		printf("              Peer SACK permitted\n");
	if (tcpr.saved.done_reading)
		printf("              Done reading\n");
	if (tcpr.saved.done_writing)
		printf("              Done writing\n");
	else if (tcpr.have_fin)
		printf("              Crashed\n");
	if (tcpr.done)
		printf("              Closed\n");
	printf("%12" PRIu32 "  Delta\n", tcpr.delta);
	printf("%12" PRIu32 "  ACK\n", ntohl(tcpr.ack));
	if (tcpr.have_fin && tcpr.saved.done_writing)
		printf("%12" PRIu32 "  FIN\n", ntohl(tcpr.fin));
	printf("%12" PRIu32 "  SEQ\n", ntohl(tcpr.seq));
	printf("%12" PRIu16 "  WIN\n", ntohs(tcpr.win));
	if (tcpr.peer.have_ack)
		printf("%12" PRIu32 "  Peer ACK\n", ntohl(tcpr.peer.ack));
	if (tcpr.peer.have_fin)
		printf("%12" PRIu32 "  Peer FIN\n", ntohl(tcpr.peer.fin));
	printf("%12" PRIu16 "  Peer WIN\n", ntohs(tcpr.peer.win));
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
		if (write(fd, &tcpr.saved, sizeof(tcpr.saved)) != sizeof(tcpr.saved)) {
			perror("Saving");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing save file");
			exit(EXIT_FAILURE);
		}
	}

	if (done && ioctl(tcprfd, TCPR_DONE) < 0) {
		perror("Marking connection done");
		exit(EXIT_FAILURE);
	}

	if (close(tcprfd) < 0) {
		perror("Closing TCPR handle");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup();
	update();
	if (wait && ioctl(tcprfd, TCPR_WAIT) < 0) {
		perror("Waiting");
		exit(EXIT_FAILURE);
	}
	print();
	teardown();
	return EXIT_SUCCESS;
}
