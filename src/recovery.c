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
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

struct recovery {
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	int sock;
	int using_tcpr;
	time_t duration;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;
	struct tcpr_connection tcpr;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Benchmark TCPR connection recovery.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b HOST[:PORT]  Bind to HOST at PORT.\n");
	fprintf(stderr, "  -c HOST[:PORT]  Connect to HOST at PORT.\n");
	fprintf(stderr, "  -d DURATION     Run for DURATION seconds.\n");
	fprintf(stderr, "  -p              Act as the peer.\n");
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

static void handle_options(struct recovery *r, int argc, char **argv)
{
	int o;

	r->bind_host = NULL;
	r->bind_port = NULL;
	r->connect_host = NULL;
	r->connect_port = NULL;
	r->using_tcpr = 1;
	r->duration = 10;

	while ((o = getopt(argc, argv, "b:c:d:p?")) != -1)
		switch (o) {
		case 'b':
			parse_address(optarg, &r->bind_host, &r->bind_port);
			break;
		case 'c':
			parse_address(optarg, &r->connect_host, &r->connect_port);
			break;
		case 'd':
			r->duration = atoi(optarg);
			break;
		case 'p':
			r->using_tcpr = 0;
			break;
		default:
			print_help_and_exit(argv[0]);
		}

	if (r->using_tcpr) {
		if (!r->connect_host && !r->connect_port && !r->bind_host && !r->bind_port)
			r->connect_host = "127.0.0.1";
		if (!r->connect_port && r->connect_host)
			r->connect_port = "9999";
		if (!r->bind_host)
			r->bind_host = "127.0.0.2";
		if (!r->bind_port)
			r->bind_port = "8888";
	} else {
		if (!r->connect_host && !r->connect_port && !r->bind_host && !r->bind_port)
			r->bind_host = "127.0.0.1";
		if (!r->bind_port && r->bind_host)
			r->bind_port = "9999";
		if (!r->connect_port && r->connect_host)
			r->connect_port = "8888";
	}
};

static void setup_connection(struct recovery *r)
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

	if (r->bind_host || r->bind_port) {
		hints.ai_flags = (r->connect_port ? 0 : AI_PASSIVE);
		err = getaddrinfo(r->bind_host, r->bind_port, &hints, &ai);
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

	if (r->connect_port) {
		hints.ai_flags = 0;
		err = getaddrinfo(r->connect_host, r->connect_port, &hints, &ai);
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

		addrlen = sizeof(r->peer_address);
		getpeername(s, (struct sockaddr *)&r->peer_address, &addrlen);

		r->sock = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(r->peer_address);
		r->sock = accept(s, (struct sockaddr *)&r->peer_address, &addrlen);;
		if (r->sock < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}

		close(s);
	}

	addrlen = sizeof(r->address);
	getsockname(r->sock, (struct sockaddr *)&r->address, &addrlen);
}

static void setup_tcpr(struct recovery *r)
{
	if (!r->using_tcpr)
		return;
	if (tcpr_setup_connection
	    (&r->tcpr, &r->peer_address, r->address.sin_port, 0) < 0) {
		perror("Error setting up TCPR");
		exit(EXIT_FAILURE);
	}
}

static void benchmark_peer(struct recovery *r)
{
	char buf[256];
	ssize_t bytes;

	for (;;) {
		bytes = read(r->sock, buf, sizeof(buf));
		if (bytes < 0) {
			perror("Error reading from socket");
			exit(EXIT_FAILURE);
		} else if (bytes == 0) {
			break;
		}
	}
}

static void fail(struct recovery *r)
{
	close(r->sock);
}

static void recover(struct recovery *r)
{
	int yes = 1;

	r->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (r->sock < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(r->sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) <
	    0) {
		perror("Setting SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}
	if (bind(r->sock, (struct sockaddr *)&r->address, sizeof(r->address)) <
	    0) {
		perror("Binding");
		exit(EXIT_FAILURE);
	}
	for (;;) {
		if (connect(r->sock, (struct sockaddr *)&r->peer_address,
		    sizeof(r->peer_address)) == 0)
		    	break;
	}
}

static void benchmark(struct recovery *r)
{
	struct timeval start;
	struct timeval end;
	unsigned long count;
	double duration;
	double mean;

	gettimeofday(&start, NULL);
	for (count = 0;; count++) {
		fail(r);
		recover(r);

		gettimeofday(&end, NULL);
		if (end.tv_sec >= start.tv_sec + r->duration)
			break;
	}

	duration = (double)end.tv_sec - (double)start.tv_sec
			+ ((double)end.tv_usec - (double)start.tv_usec) / 10e6;
	mean = duration / (double)count;
	printf("%lf\t%lu\t%lf\n", duration, count, mean);
}

static void teardown_connection(struct recovery *r)
{
	if (r->using_tcpr) {
		tcpr_done_writing(&r->tcpr);
		tcpr_done_reading(&r->tcpr);
	}
	if (close(r->sock) < 0)
		perror("Closing connection");
}

static void teardown_tcpr(struct recovery *r)
{
	if (r->using_tcpr)
		tcpr_teardown_connection(&r->tcpr);
}

int main(int argc, char **argv)
{
	struct recovery r;

	handle_options(&r, argc, argv);

	setup_connection(&r);
	setup_tcpr(&r);

	if (!r.using_tcpr)
		benchmark_peer(&r);
	else
		benchmark(&r);

	teardown_connection(&r);
	teardown_tcpr(&r);

	return EXIT_SUCCESS;
}
