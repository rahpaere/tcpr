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

struct latency {
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	int peer;
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
	fprintf(stderr, "Benchmark TCPR latency.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b HOST[:PORT]  Bind to HOST at PORL.\n");
	fprintf(stderr, "  -c HOST[:PORT]  Connect to HOST at PORL.\n");
	fprintf(stderr, "  -d DURATION     Run for DURATION seconds.\n");
	fprintf(stderr, "  -n COUNT        Measure COUNT times.\n");
	fprintf(stderr, "  -p              Act as the peer.\n");
	fprintf(stderr, "  -C              Bypass checkpointed acknowledgments.\n");
	fprintf(stderr, "  -T              Bypass TCPR.\n");
	fprintf(stderr, "  -?              "
		"Print this help message and exil.\n");
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

static void handle_options(struct latency *l, int argc, char **argv)
{
	int o;

	l->bind_host = NULL;
	l->bind_port = NULL;
	l->connect_host = NULL;
	l->connect_port = NULL;
	l->using_tcpr = -1;
	l->peer = 0;
	l->checkpointing = 1;
	l->duration = 6;
	l->count = 10;

	while ((o = getopt(argc, argv, "b:c:d:n:pCT?")) != -1)
		switch (o) {
		case 'b':
			parse_address(optarg, &l->bind_host, &l->bind_port);
			break;
		case 'c':
			parse_address(optarg, &l->connect_host, &l->connect_port);
			break;
		case 'd':
			l->duration = atoi(optarg);
			break;
		case 'n':
			l->count = atoi(optarg);
			break;
		case 'p':
			l->peer = 1;
			break;
		case 'C':
			l->checkpointing = 0;
			break;
		case 'T':
			l->using_tcpr = 0;
			break;
		default:
			print_help_and_exit(argv[0]);
		}

	if (l->using_tcpr == -1)
		l->using_tcpr = !l->peer;
	if (l->peer) {
		if (!l->connect_host && !l->connect_port && !l->bind_host && !l->bind_port)
			l->bind_host = "127.0.0.1";
		if (!l->bind_port && l->bind_host)
			l->bind_port = "9999";
		if (!l->connect_port && l->connect_host)
			l->connect_port = "8888";
	} else {
		if (!l->connect_host && !l->connect_port && !l->bind_host && !l->bind_port)
			l->connect_host = "127.0.0.1";
		if (!l->connect_port && l->connect_host)
			l->connect_port = "9999";
		if (!l->bind_host)
			l->bind_host = l->using_tcpr ? "127.0.0.2" : "127.0.0.1";
		if (!l->bind_port)
			l->bind_port = l->using_tcpr ? "8888" : "7777";
	}
};

static void setup_connection(struct latency *l)
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

	if (l->bind_host || l->bind_port) {
		hints.ai_flags = (l->connect_port ? 0 : AI_PASSIVE);
		err = getaddrinfo(l->bind_host, l->bind_port, &hints, &ai);
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

	if (l->connect_port) {
		hints.ai_flags = 0;
		err = getaddrinfo(l->connect_host, l->connect_port, &hints, &ai);
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

		addrlen = sizeof(l->peer_address);
		getpeername(s, (struct sockaddr *)&l->peer_address, &addrlen);

		l->sock = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(l->peer_address);
		l->sock = accept(s, (struct sockaddr *)&l->peer_address, &addrlen);;
		if (l->sock < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}

		close(s);
	}

	addrlen = sizeof(l->address);
	getsockname(l->sock, (struct sockaddr *)&l->address, &addrlen);
}

static void setup_tcpr(struct latency *l)
{
	if (!l->using_tcpr)
		return;
	if (tcpr_setup_connection
	    (&l->tcpr, &l->peer_address, l->address.sin_port, 0) < 0) {
		perror("Error setting up TCPR");
		exit(EXIT_FAILURE);
	}
}

static void benchmark_peer(struct latency *l)
{
	char msg = '\n';
	struct timeval end;
	struct timeval start;
	ssize_t bytes;
	unsigned long total;
	double duration;
	double mean;
	int count;

	for (count = 0; count < l->count; count++) {
		total = 0;
		gettimeofday(&start, NULL);
		do {
			bytes = read(l->sock, &msg, sizeof(msg));
			if (bytes == 0) {
				gettimeofday(&end, NULL);
				break;
			} else if (bytes != sizeof(msg)) {
				perror("Error reading");
				exit(EXIT_FAILURE);
			}

			bytes = write(l->sock, &msg, sizeof(msg));
			if (bytes != sizeof(msg)) {
				perror("Error writing");
				exit(EXIT_FAILURE);
			}

			total++;
			gettimeofday(&end, NULL);
		} while (count + 1 == l->count || end.tv_sec < start.tv_sec + l->duration);
		duration = (double)end.tv_sec - (double)start.tv_sec +
			((double)end.tv_usec - (double)start.tv_usec) / 10e6;
		mean = duration / (double)total;
		printf("%lf\t%lu\t%lf\n", duration, total, mean);
	}
}

static void benchmark(struct latency *l)
{
	char msg = '\n';
	struct timeval end;
	struct timeval start;
	ssize_t bytes;
	unsigned long total;
	double duration;
	double mean;
	int count;

	if (l->using_tcpr && !l->checkpointing)
		tcpr_done_reading(&l->tcpr);

	for (count = 0; count < l->count; count++) {
		total = 0;
		gettimeofday(&start, NULL);
		do {
			bytes = write(l->sock, &msg, sizeof(msg));
			if (bytes != sizeof(msg)) {
				perror("Error writing");
				exit(EXIT_FAILURE);
			}

			bytes = read(l->sock, &msg, sizeof(msg));
			if (bytes != sizeof(msg)) {
				perror("Error reading");
				exit(EXIT_FAILURE);
			}
			if (l->using_tcpr && l->checkpointing)
				tcpr_consume(&l->tcpr, sizeof(msg));

			total++;
			gettimeofday(&end, NULL);
		} while (end.tv_sec < start.tv_sec + l->duration);
		duration = (double)end.tv_sec - (double)start.tv_sec +
			((double)end.tv_usec - (double)start.tv_usec) / 10e6;
		mean = duration / (double)total;
		printf("%lf\t%lu\t%lf\n", duration, total, mean);
	}
}

static void teardown_connection(struct latency *l)
{
	if (l->using_tcpr) {
		tcpr_done_writing(&l->tcpr);
		tcpr_done_reading(&l->tcpr);
	}
	if (close(l->sock) < 0)
		perror("Closing connection");
}

static void teardown_tcpr(struct latency *l)
{
	if (l->using_tcpr)
		tcpr_teardown_connection(&l->tcpr);
}

int main(int argc, char **argv)
{
	struct latency l;

	handle_options(&l, argc, argv);

	setup_connection(&l);
	setup_tcpr(&l);

	if (l.peer)
		benchmark_peer(&l);
	else
		benchmark(&l);

	teardown_connection(&l);
	teardown_tcpr(&l);

	return EXIT_SUCCESS;
}
