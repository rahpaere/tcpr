#include <tcpr/types.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUM_CONNECTIONS 256

static char *tcpr_address;
static char *bind_address;
static char *connect_address;

static int listen_sock = -1;
static int tcpr_sock = -1;

struct connection {
	int sock;
	struct sockaddr_in addr;
	struct sockaddr_in peer_addr;
	struct tcpr_ip4 state;
} connections[NUM_CONNECTIONS];

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Benchmark recovery.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b [HOST:]PORT  Bind to HOST:PORT.\n");
	fprintf(stderr, "  -c [HOST:]PORT  Connect to HOST:PORT.\n");
	fprintf(stderr, "  -t [HOST:]PORT  Connect to TCPR at HOST:PORT.\n");
	fprintf(stderr, "  -?              Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
        for (;;)
                switch (getopt(argc, argv, "b:c:t:Cv?")) {
                case 'b':
                        bind_address = optarg;
                        break;
                case 'c':
                        connect_address = optarg;
                        break;
                case 't':
                        tcpr_address = optarg;
                        break;
                case -1:
                        return;
                default:
                        print_help_and_exit(argv[0]);
                }
}
static void open_listening_socket(void)
{
	char *port;
	char *host;
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

	port = strchr(bind_address, ':');
	if (port) {
		host = bind_address;
		*port++ = '\0';
	} else {
		port = bind_address;
		host = NULL;
	}
	err = getaddrinfo(host, port, &hints, &ai);
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

	listen_sock = s;
}

static void accept_connection(struct connection *c)
{
	c->sock = accept(listen_sock, NULL, NULL);
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
	if (err < 0 && !tcpr_address) {
		perror("Consuming input");
		exit(EXIT_FAILURE);
	}
	close(c->sock);
}

static void close_listening_socket(void)
{
	close(listen_sock);
}

static void setup_tcpr(void)
{
        char *host;
        char *port;
        int err;
        int s;
        struct addrinfo *ai;
        struct addrinfo hints;

        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s < 0) {
                perror("Creating socket");
                exit(EXIT_FAILURE);
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        port = strchr(tcpr_address, ':');
        if (port) {
                host = tcpr_address;
                *port++ = '\0';
        } else {
                port = tcpr_address;
                host = NULL;
        }

        err = getaddrinfo(host, port, &hints, &ai);
        if (err) {
                fprintf(stderr, "Resolving \"%s\": %s\n", tcpr_address, gai_strerror(err));
                exit(EXIT_FAILURE);
        }

        if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
                perror("Connecting to TCPR");
                exit(EXIT_FAILURE);
        }

        tcpr_sock = s;
}

static void open_benchmark_socket(struct connection *c)
{
	static char *host;
	static char *port;
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

	if (!port) {
		port = strchr(connect_address, ':');
		if (port) {
			host = connect_address;
			*port++ = '\0';
		} else {
			port = connect_address;
			host = NULL;
		}
	}
	err = getaddrinfo(host, port, &hints, &ai);
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

	c->state.address = c->addr.sin_addr.s_addr;
	c->state.peer_address = c->peer_addr.sin_addr.s_addr;
	c->state.tcpr.hard.port = c->addr.sin_port;
	c->state.tcpr.hard.peer.port = c->peer_addr.sin_port;

	send(tcpr_sock, &c->state, sizeof(c->state), 0);
	recv(tcpr_sock, &c->state, sizeof(c->state), 0);
}

static void fail(struct connection *c)
{
	c->state.tcpr.failed = 1;
	c->state.tcpr.done = 1;
	send(tcpr_sock, &c->state, sizeof(c->state), 0);
	reap_connection(c);
}

static void recover(struct connection *c)
{
	int s;
	int yes = 1;

	c->state.tcpr.failed = 0;
	c->state.tcpr.done = 0;
	send(tcpr_sock, &c->state, sizeof(c->state), 0);

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

static void teardown(struct connection *c)
{
	c->state.tcpr.hard.done_reading = 1;
	c->state.tcpr.hard.done_writing = 1;
	send(tcpr_sock, &c->state, sizeof(c->state), 0);
	shutdown(c->sock, SHUT_WR);
	reap_connection(c);
}

void teardown_tcpr(void)
{
	close(tcpr_sock);
}

int main(int argc, char **argv)
{
	struct timespec start;
	struct timespec end;
	double t;
	int i;

	handle_options(argc, argv);

	if (!tcpr_address) {
		open_listening_socket();
		for (i = 0; i < NUM_CONNECTIONS; i++)
			accept_connection(&connections[i]);
		close_listening_socket();
		for (i = 0; i < NUM_CONNECTIONS; i++)
			reap_connection(&connections[i]);
		return EXIT_SUCCESS;
	}

	setup_tcpr();

	for (i = 0; i < NUM_CONNECTIONS; i++)
		open_benchmark_socket(&connections[i]);
	for (i = 0; i < NUM_CONNECTIONS; i++)
		fail(&connections[i]);

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
	teardown_tcpr();

	return EXIT_SUCCESS;
}
