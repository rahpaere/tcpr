#include <tcpr/types.h>

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
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

static char *tcpr_address;
static char *bind_address;
static char *connect_address;

static const char *save_file;
static const char *recovery_file;

static int saved_bytes;
static int done_reading;
static int done_writing;
static int done;
static int kill;

static struct tcpr_ip4 state;

static int tcpr_sock;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Read and write TCPR connection state.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b [HOST:]PORT  The application is bound to HOST:PORT.\n");
	fprintf(stderr, "  -c [HOST:]PORT  The application is connected to HOST:PORT.\n");
	fprintf(stderr, "  -t [HOST:]PORT  Connect to TCPR at HOST:PORT.\n");
	fprintf(stderr, "  -s FILE         Save the connection state into FILE.\n");
	fprintf(stderr, "  -r FILE         Recover the connection state from FILE.\n");
	fprintf(stderr, "  -i NUM          Acknowledge NUM bytes of input.\n");
	fprintf(stderr, "  -d reading      Shut down reading.\n");
	fprintf(stderr, "  -d writing      Shut down reading.\n");
	fprintf(stderr, "  -d done         Finish off the connection.\n");
	fprintf(stderr, "  -k              Reset the application.\n");
	fprintf(stderr, "  -?              Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "b:c:t:s:r:i:d:k?")) {
		case 'b':
			bind_address = optarg;
			break;
		case 'c':
			connect_address = optarg;
			break;
		case 't':
			tcpr_address = optarg;
			break;
		case 's':
			save_file = optarg;
			break;
		case 'r':
			recovery_file = optarg;
			break;
		case 'i':
			saved_bytes = atoi(optarg);
			break;
		case 'd':
			if (strcmp(optarg, "done") == 0)
				done = 1;
			else if (strcmp(optarg, "reading") == 0)
				done_reading = 1;
			else if (strcmp(optarg, "writing") == 0)
				done_writing = 1;
			break;
		case 'k':
			kill = 1;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void lookup(char *address, int socktype, int protocol,
		   struct sockaddr_in *sa)
{
	char *host;
	char *port;
	struct addrinfo *ai;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;

	port = strchr(address, ':');
	if (port) {
		host = address;
		*port++ = '\0';
	} else {
		port = address;
		host = NULL;
	}

	err = getaddrinfo(host, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving \"%s\": %s\n", address,
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	memcpy(sa, ai->ai_addr, sizeof(*sa));
	freeaddrinfo(ai);
}

static void setup(void)
{
	struct sockaddr_in sa;

	lookup(bind_address, SOCK_STREAM, IPPROTO_TCP, &sa);
	state.address = sa.sin_addr.s_addr;
	state.tcpr.hard.port = sa.sin_port;

	lookup(connect_address, SOCK_STREAM, IPPROTO_TCP, &sa);
	state.peer_address = sa.sin_addr.s_addr;
	state.tcpr.hard.peer.port = sa.sin_port;

	tcpr_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (tcpr_sock < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	lookup(tcpr_address, SOCK_DGRAM, IPPROTO_UDP, &sa);
	if (connect(tcpr_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("Connecting");
		exit(EXIT_FAILURE);
	}

	send(tcpr_sock, &state, sizeof(state), 0);
	recv(tcpr_sock, &state, sizeof(state), 0);
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
		if (read(fd, &state.tcpr.hard, sizeof(state.tcpr.hard)) != sizeof(state.tcpr.hard)) {
			perror("Recovering");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing recovery file");
			exit(EXIT_FAILURE);
		}
	}

	if (done_writing)
		state.tcpr.hard.done_writing = 1;
	if (done_reading)
		state.tcpr.hard.done_reading = 1;
	if (done)
		state.tcpr.done = 1;
	if (saved_bytes > 0)
		state.tcpr.hard.ack = htonl(ntohl(state.tcpr.hard.ack) + saved_bytes);
	if (kill)
		state.tcpr.failed = 1;

	send(tcpr_sock, &state, sizeof(state), 0);
	if (saved_bytes <= 0 || !kill)
		recv(tcpr_sock, &state, sizeof(state), 0);
}

static void print(void)
{
	if (state.tcpr.hard.port)
		printf("%12" PRIu16 "  External port\n", ntohs(state.tcpr.hard.port));
	if (state.tcpr.port)
		printf("%12" PRIu16 "  Internal port\n", ntohs(state.tcpr.port));
	if (state.tcpr.hard.peer.port)
		printf("%12" PRIu16 "  Peer port\n",
			ntohs(state.tcpr.hard.peer.port));
	printf("%12" PRIu32 "  Checkpointed ACK\n", ntohl(state.tcpr.hard.ack));
	if (state.tcpr.hard.peer.mss)
		printf("%12" PRIu16 "  Peer MSS\n", state.tcpr.hard.peer.mss);
	if (state.tcpr.hard.peer.ws)
		printf("%12" PRIu8 "  Peer WS\n", state.tcpr.hard.peer.ws - 1);
	if (state.tcpr.hard.peer.sack_permitted)
		printf("              Peer SACK permitted\n");
	if (state.tcpr.hard.done_reading)
		printf("              Done reading\n");
	if (state.tcpr.hard.done_writing)
		printf("              Done writing\n");
	else if (state.tcpr.have_fin)
		printf("              Crashed\n");
	if (state.tcpr.done)
		printf("              Closed\n");
	printf("%12" PRIu32 "  Delta\n", state.tcpr.delta);
	printf("%12" PRIu32 "  ACK\n", ntohl(state.tcpr.ack));
	if (state.tcpr.have_fin && state.tcpr.hard.done_writing)
		printf("%12" PRIu32 "  FIN\n", ntohl(state.tcpr.fin));
	printf("%12" PRIu32 "  SEQ\n", ntohl(state.tcpr.seq));
	printf("%12" PRIu16 "  WIN\n", ntohs(state.tcpr.win));
	if (state.tcpr.peer.have_ack)
		printf("%12" PRIu32 "  Peer ACK\n", ntohl(state.tcpr.peer.ack));
	if (state.tcpr.peer.have_fin)
		printf("%12" PRIu32 "  Peer FIN\n", ntohl(state.tcpr.peer.fin));
	printf("%12" PRIu16 "  Peer WIN\n", ntohs(state.tcpr.peer.win));
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
		if (write(fd, &state.tcpr.hard, sizeof(state.tcpr.hard)) != sizeof(state.tcpr.hard)) {
			perror("Saving");
			exit(EXIT_FAILURE);
		}
		if (close(fd) < 0) {
			perror("Closing save file");
			exit(EXIT_FAILURE);
		}
	}

	if (close(tcpr_sock) < 0) {
		perror("Closing TCPR handle");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup();
	update();
	print();
	teardown();
	return EXIT_SUCCESS;
}
