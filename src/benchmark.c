#include <tcpr/application.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define NUM_CONNECTIONS 256

static const char *internal_host = "10.0.1.1";
static const char *peer_host = "10.0.0.2";
static const char *peer_port = "9999";
static int running_peer;
static int listening_socket;

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
	fprintf(stderr, "  -P       Run as the peer.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "i:h:p:P?")) {
		case 'i':
			internal_host = optarg;
			break;
		case 'h':
			peer_host = optarg;
			break;
		case 'p':
			peer_port = optarg;
			break;
		case 'P':
			running_peer = 1;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void open_listening_socket(void)
{
	int err;
	int s;
	int yes = 1;
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
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(NULL, peer_port, &hints, &ai);
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

	if (listen(s, NUM_CONNECTIONS) < 0) {
		perror("Listening");
		exit(EXIT_FAILURE);
	}

	listening_socket = s;
}

static void accept_connection(struct connection *c)
{
	c->sock = accept(listening_socket, NULL, NULL);
	if (c->sock < 0) {
		perror("Accepting");
		exit(EXIT_FAILURE);
	}
}

static void reap_connection(struct connection *c)
{
	char buf[64];
	int err;

	do {
		err = read(c->sock, buf, sizeof(buf));
	} while (err > 0);
	if (err < 0) {
		perror("Consuming input");
		exit(EXIT_FAILURE);
	}
	close(c->sock);
}

static void close_listening_socket(void)
{
	close(listening_socket);
}

static void open_benchmark_socket(struct connection *c)
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
}

static void fail(struct connection *c)
{
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

	if (tcpr_setup_connection(&c->tcpr, c->peer_addr.sin_addr.s_addr, c->peer_addr.sin_port, c->addr.sin_port, 0) < 0) {
		perror("Recovering, setting up TCPR");
		exit(EXIT_FAILURE);
	}

	c->sock = s;
}

static void teardown(struct connection *c)
{
	char buf[64];
	int err;

	tcpr_close(&c->tcpr);
	tcpr_teardown_connection(&c->tcpr);

	shutdown(c->sock, SHUT_WR);
	do {
		err = read(c->sock, buf, sizeof(buf));
	} while (err > 0);
	if (err < 0) {
		perror("Consuming input");
		exit(EXIT_FAILURE);
	}

	close(c->sock);
}

int main(int argc, char **argv)
{
	struct timespec start;
	struct timespec end;
	double t;
	int i;

	handle_options(argc, argv);

	if (running_peer) {
		open_listening_socket();
		for (i = 0; i < NUM_CONNECTIONS; i++)
			accept_connection(&connections[i]);
		close_listening_socket();
		for (i = 0; i < NUM_CONNECTIONS; i++)
			reap_connection(&connections[i]);
		return EXIT_SUCCESS;
	}

	for (i = 0; i < NUM_CONNECTIONS; i++)
		open_benchmark_socket(&connections[i]);

	//sleep(30);

	for (i = 0; i < NUM_CONNECTIONS; i++)
		fail(&connections[i]);

	sleep(30);

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < NUM_CONNECTIONS; i++)
		recover(&connections[i]);
	clock_gettime(CLOCK_REALTIME, &end);

	t = (double)end.tv_sec + (double)end.tv_nsec / 1e9;
	t -= (double)start.tv_sec + (double)start.tv_nsec / 1e9;
	t /= (double)NUM_CONNECTIONS;
	printf("%lf\n", t);

	for (i = 0; i < NUM_CONNECTIONS; i++)
		teardown(&connections[i]);

	return EXIT_SUCCESS;
}
