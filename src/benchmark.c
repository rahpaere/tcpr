#include <tcpr/application.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define NUM_CONNECTIONS 32

static const char *internal_host = "10.0.1.1";
static const char *peer_host = "10.0.0.2";
static const char *peer_port = "echo";

struct connection {
	int sock;
	struct sockaddr_in addr;
	struct sockaddr_in peer_addr;
	struct tcpr_connection tcpr;
} connections[NUM_CONNECTIONS];

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Benchmark recovery.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -i HOST  Internally, the application is bound to HOST.\n");
	fprintf(stderr, "  -h HOST  The peer is bound to HOST.\n");
	fprintf(stderr, "  -p PORT  The peer is bound to PORT.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "i:h:p:?")) {
		case 'i':
			internal_host = optarg;
			break;
		case 'h':
			peer_host = optarg;
			break;
		case 'p':
			peer_port = optarg;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void open_and_fail(struct connection *c)
{
	int err;
	int s;
	int yes = 1;
	socklen_t addrlen;
	struct addrinfo *ai;
	struct addrinfo hints;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("Setting SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(internal_host, NULL, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving bind address: %s\n",
				gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Binding");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);

	err = getaddrinfo(peer_host, peer_port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving peer address: %s\n",
				gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Connecting");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);

	c->sock = s;

	addrlen = sizeof(c->peer_addr);
	getpeername(s, (struct sockaddr *)&c->peer_addr, &addrlen);

	addrlen = sizeof(c->addr);
	getsockname(s, (struct sockaddr *)&c->addr, &addrlen);

	close(c->sock);
}

static void recover(struct connection *c)
{
	int s;
	int yes = 1;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("Recovering, creating socket");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("Recovering, setting SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr *)&c->addr, sizeof(c->addr)) < 0) {
		perror("Recovering, binding");
		exit(EXIT_FAILURE);
	}

	if (connect(s, (struct sockaddr *)&c->peer_addr, sizeof(c->peer_addr)) < 0) {
		perror("Recovering, connecting");
		exit(EXIT_FAILURE);
	}

	c->sock = s;
}

static void resetup(struct connection *c)
{
	if (tcpr_setup_connection(&c->tcpr, c->peer_addr.sin_addr.s_addr, c->peer_addr.sin_port, c->addr.sin_port, 0) < 0) {
		perror("Recovering, setting up TCPR");
		exit(EXIT_FAILURE);
	}
}

static void teardown(struct connection *c)
{
	char buf[64];
	int err;

	tcpr_close(&c->tcpr);

	shutdown(c->sock, SHUT_WR);
	do {
		err = read(c->sock, buf, sizeof(buf));
	} while (err > 0);
	if (err < 0) {
		perror("Consuming input");
		exit(EXIT_FAILURE);
	}

	close(c->sock);
	tcpr_wait(&c->tcpr);
	tcpr_teardown_connection(&c->tcpr);
}

int main(int argc, char **argv)
{
	struct timespec start;
	struct timespec end;
	double recover_time;
	double resetup_time;
	int i;

	handle_options(argc, argv);

	for (i = 0; i < NUM_CONNECTIONS; i++)
		open_and_fail(&connections[i]);

	sleep(1);

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < NUM_CONNECTIONS; i++)
		recover(&connections[i]);
	clock_gettime(CLOCK_REALTIME, &end);

	recover_time = (double)end.tv_sec + (double)end.tv_nsec / 1e9;
	recover_time -= (double)start.tv_sec + (double)start.tv_nsec / 1e9;
	recover_time /= (double)NUM_CONNECTIONS;

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < NUM_CONNECTIONS; i++)
		resetup(&connections[i]);
	clock_gettime(CLOCK_REALTIME, &end);

	resetup_time = (double)end.tv_sec + (double)end.tv_nsec / 1e9;
	resetup_time -= (double)start.tv_sec + (double)start.tv_nsec / 1e9;
	resetup_time /= (double)NUM_CONNECTIONS;

	printf("Recover,Resetup\n");
	printf("%lf,%lf\n", recover_time, resetup_time);

	for (i = 0; i < NUM_CONNECTIONS; i++)
		teardown(&connections[i]);

	return EXIT_SUCCESS;
}
