#include <tcpr/application.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

struct throughput {
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	int peer;
	int sending;
	int sock;
	int using_tcpr;
	int checkpointing;
	int count;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;
	struct tcpr_connection tcpr;
	time_t duration;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Benchmark TCPR throughput.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b HOST[:PORT]  Bind to HOST at PORT.\n");
	fprintf(stderr, "  -c HOST[:PORT]  Connect to HOST at PORT.\n");
	fprintf(stderr, "  -d DURATION     Run for DURATION seconds.\n");
	fprintf(stderr, "  -n COUNT        Measure COUNT times.\n");
	fprintf(stderr, "  -p              Act as the peer.\n");
	fprintf(stderr, "  -r              Send data from peer.\n");
	fprintf(stderr, "  -C              "
		"Bypass checkpointed acknowledgments.\n");
	fprintf(stderr, "  -T              Bypass TCPR.\n");
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

static void handle_options(struct throughput *t, int argc, char **argv)
{
	int o;

	t->bind_host = NULL;
	t->bind_port = NULL;
	t->connect_host = NULL;
	t->connect_port = NULL;
	t->using_tcpr = -1;
	t->peer = 0;
	t->checkpointing = 1;
	t->sending = 1;
	t->duration = 6;
	t->count = 10;

	while ((o = getopt(argc, argv, "b:c:d:n:prCT?")) != -1)
		switch (o) {
		case 'b':
			parse_address(optarg, &t->bind_host, &t->bind_port);
			break;
		case 'c':
			parse_address(optarg, &t->connect_host, &t->connect_port);
			break;
		case 'd':
			t->duration = atoi(optarg);
			break;
		case 'n':
			t->count = atoi(optarg);
			break;
		case 'p':
			t->peer = 1;
			break;
		case 'r':
			t->sending = !t->sending;
			break;
		case 'C':
			t->checkpointing = 0;
			break;
		case 'T':
			t->using_tcpr = 0;
			break;
		default:
			print_help_and_exit(argv[0]);
		}

	if (t->using_tcpr == -1)
		t->using_tcpr = !t->peer;
	if (t->peer)
		t->sending = !t->sending;
	if (t->peer) {
		if (!t->connect_host && !t->connect_port && !t->bind_host && !t->bind_port)
			t->bind_host = "127.0.0.1";
		if (!t->bind_port && t->bind_host)
			t->bind_port = "9999";
		if (!t->connect_port && t->connect_host)
			t->connect_port = "8888";
	} else {
		if (!t->connect_host && !t->connect_port && !t->bind_host && !t->bind_port)
			t->connect_host = "127.0.0.1";
		if (!t->connect_port && t->connect_host)
			t->connect_port = "9999";
		if (!t->bind_host)
			t->bind_host = t->using_tcpr ? "127.0.0.2" : "127.0.0.1";
		if (!t->bind_port)
			t->bind_port = t->using_tcpr ? "8888" : "7777";
	}
};

static void setup_connection(struct throughput *t)
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

	if (t->bind_host || t->bind_port) {
		hints.ai_flags = (t->connect_port ? 0 : AI_PASSIVE);
		err = getaddrinfo(t->bind_host, t->bind_port, &hints, &ai);
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
	}

	if (t->connect_port) {
		hints.ai_flags = 0;
		err = getaddrinfo(t->connect_host, t->connect_port, &hints, &ai);
		if (err) {
			fprintf(stderr, "Resolving peer address: %s\n",
					gai_strerror(err));
			exit(EXIT_FAILURE);
		}

		while (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Connecting");
			if (errno != ECONNREFUSED)
				exit(EXIT_FAILURE);
			sleep(2);
		}

		freeaddrinfo(ai);

		addrlen = sizeof(t->peer_address);
		getpeername(s, (struct sockaddr *)&t->peer_address, &addrlen);

		t->sock = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(t->peer_address);
		t->sock = accept(s, (struct sockaddr *)&t->peer_address, &addrlen);;
		if (t->sock < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}

		close(s);
	}

	addrlen = sizeof(t->address);
	getsockname(t->sock, (struct sockaddr *)&t->address, &addrlen);
}

static void setup_tcpr(struct throughput *t)
{
	if (!t->using_tcpr)
		return;
	if (tcpr_setup_connection
	    (&t->tcpr, &t->peer_address, t->address.sin_port, 0) < 0) {
		perror("Error setting up TCPR");
		exit(EXIT_FAILURE);
	}
}

static void benchmark_sending(struct throughput *t)
{
	char buffer[4096];
	struct timeval end;
	struct timeval start;
	ssize_t bytes;
	unsigned long total;
	double duration;
	double mean;
	int count;

	memset(buffer, '\n', sizeof(buffer));
	for (count = 0; count < t->count; count++) {
		total = 0;
		gettimeofday(&start, NULL);
		do {
			bytes = write(t->sock, buffer, sizeof(buffer));
			if (bytes < 0) {
				perror("Error writing");
				exit(EXIT_FAILURE);
			}

			total += bytes;
			gettimeofday(&end, NULL);
		} while (end.tv_sec < start.tv_sec + t->duration);
		duration = (double)end.tv_sec - (double)start.tv_sec +
			((double)end.tv_usec - (double)start.tv_usec) / 10e6;
		mean = (double)total / duration;
		printf("%lf\t%lu\t%lf\n", duration, total, mean);
	}
}

static void benchmark_receiving(struct throughput *t)
{
	char buffer[4096];
	struct timeval end;
	struct timeval start;
	ssize_t bytes;
	unsigned long total;
	double duration;
	double mean;
	int count;

	if (t->using_tcpr && !t->checkpointing)
		tcpr_done_reading(&t->tcpr);

	for (count = 0; count < t->count; count++) {
		total = 0;
		gettimeofday(&start, NULL);
		do {
			bytes = read(t->sock, buffer, sizeof(buffer));
			if (bytes < 0) {
				perror("Error reading");
				exit(EXIT_FAILURE);
			}

			total += bytes;
			if (t->using_tcpr && t->checkpointing)
				tcpr_consume(&t->tcpr, bytes);

			gettimeofday(&end, NULL);
		} while (bytes && (count + 1 == t->count || end.tv_sec < start.tv_sec + t->duration));
		duration = (double)end.tv_sec - (double)start.tv_sec +
			((double)end.tv_usec - (double)start.tv_usec) / 10e6;
		mean = (double)total / duration;
		printf("%lf\t%lu\t%lf\n", duration, total, mean);
	}
}

static void teardown_connection(struct throughput *t)
{
	if (t->using_tcpr) {
		tcpr_done_writing(&t->tcpr);
		tcpr_done_reading(&t->tcpr);
		if (shutdown(t->sock, SHUT_RDWR) < 0)
			perror("Shutting down connection");
		while (!t->tcpr.state->done)
			sleep(1);
	}
	if (close(t->sock) < 0)
		perror("Closing connection");
}

static void teardown_tcpr(struct throughput *t)
{
	if (t->using_tcpr)
		tcpr_teardown_connection(&t->tcpr);
}

int main(int argc, char **argv)
{
	struct throughput t;

	handle_options(&t, argc, argv);

	setup_connection(&t);
	setup_tcpr(&t);

	if (t.sending)
		benchmark_sending(&t);
	else
		benchmark_receiving(&t);

	teardown_connection(&t);
	teardown_tcpr(&t);

	return EXIT_SUCCESS;
}
