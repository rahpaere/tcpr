#include <tcpr/types.h>

#include <arpa/inet.h>
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

static const char state_path_format[] = "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".state";
static const char ctl_path_format[] = "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".ctl";

struct chat {
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	int ctl_socket;
	int epoll_fd;
	int peer_socket;
	int using_tcpr;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;
	struct sockaddr_un ctl_address;
	struct tcpr *state;
};

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Make or accept a connection with a remote peer, "
		"optionally protecting\nthe connection with TCPR.  Forward "
		"standard input to the peer and print\ndata received to "
		"standard output.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b HOST[:PORT]  Bind to HOST at PORT.\n");
	fprintf(stderr, "  -c HOST[:PORT]  Connect to HOST at PORT.\n");
	fprintf(stderr, "  -p              "
		"Act as the peer; that is, do not use TCPR.\n");
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

static void handle_options(struct chat *c, int argc, char **argv)
{
	int o;

	c->bind_host = NULL;
	c->bind_port = NULL;
	c->connect_host = NULL;
	c->connect_port = NULL;
	c->using_tcpr = 1;

	while ((o = getopt(argc, argv, "b:c:p?")) != -1)
		switch (o) {
		case 'b':
			parse_address(optarg, &c->bind_host, &c->bind_port);
			break;
		case 'c':
			parse_address(optarg, &c->connect_host, &c->connect_port);
			break;
		case 'p':
			c->using_tcpr = 0;
			break;
		default:
			print_help_and_exit(argv[0]);
		}

	if (!c->connect_port && !c->connect_host && !c->bind_port && !c->bind_host) {
		if (c->using_tcpr) {
			c->bind_host = "127.0.0.2";
		} else {
			c->connect_host = "127.0.0.1";
			c->bind_host = "127.0.0.1";
			c->bind_port = "9999";
		}
	}
	if (!c->connect_port && c->connect_host)
		c->connect_port = "8888";
	if (!c->bind_port && c->bind_host)
		c->bind_port = "8888";
};

static void setup_connection(struct chat *c)
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
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
		perror("Setting TCP_NODELAY");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (c->bind_host || c->bind_port) {
		hints.ai_flags = (c->connect_port ? 0 : AI_PASSIVE);
		err = getaddrinfo(c->bind_host, c->bind_port, &hints, &ai);
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

	if (c->connect_port) {
		hints.ai_flags = 0;
		err = getaddrinfo(c->connect_host, c->connect_port, &hints, &ai);
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
		c->peer_socket = s;

		addrlen = sizeof(c->peer_address);
		getpeername(c->peer_socket, (struct sockaddr *)&c->address, &addrlen);
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(c->peer_address);
		c->peer_socket = accept(s, (struct sockaddr *)&c->peer_address, &addrlen);
		if (c->peer_socket < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}

		close(s);
	}

	addrlen = sizeof(c->address);
	getsockname(c->peer_socket, (struct sockaddr *)&c->address, &addrlen);
}

static struct tcpr *get_state(struct sockaddr_in *peer_address, uint16_t port, int create)
{
	char host[INET_ADDRSTRLEN];
	char path[sizeof(state_path_format) + sizeof(host) + 10];
	int flags;
	int fd;
	struct tcpr *state;

	inet_ntop(AF_INET, &peer_address->sin_addr, host, sizeof(host));
	sprintf(path, state_path_format, host, ntohs(peer_address->sin_port), ntohs(port));

	flags = O_RDWR;
	if (create)
		flags |= O_CREAT;
	fd = open(path, flags, 0600);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, sizeof(*state)) < 0) {
		close(fd);
		return NULL;
	}

	flags = PROT_READ | PROT_WRITE;
	state = mmap(NULL, sizeof(*state), flags, MAP_SHARED, fd, 0);
	close(fd);
	return state == MAP_FAILED ? NULL : state;
}

static void teardown_state(struct tcpr *state)
{
	munmap(state, sizeof(*state));
}

static void setup_ctl_address(struct sockaddr_un *ctl_address, struct sockaddr_in *peer_address, uint16_t port)
{
	char host[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &peer_address->sin_addr, host, sizeof(host));
	memset(ctl_address, 0, sizeof(*ctl_address));
	ctl_address->sun_family = AF_UNIX;
	sprintf(ctl_address->sun_path, ctl_path_format, host, ntohs(peer_address->sin_port), ntohs(port));
}

static int get_ctl(void)
{
	return socket(AF_UNIX, SOCK_DGRAM, 0);
}

static void teardown_ctl(int s)
{
	close(s);
}

static void setup_tcpr(struct chat *c)
{
	if (!c->using_tcpr)
		return;

	c->state = get_state(&c->peer_address, c->address.sin_port, 0);
	if (!c->state) {
		fprintf(stderr, "Could not get TCPR state.\n");
		exit(EXIT_FAILURE);
	}

	c->ctl_socket = get_ctl();
	if (c->ctl_socket < 0) {
		fprintf(stderr, "Could not get control socket.\n");
		exit(EXIT_FAILURE);
	}

	setup_ctl_address(&c->ctl_address, &c->peer_address,
			  c->address.sin_port);
}

static void setup_events(struct chat *c)
{
	c->epoll_fd = epoll_create1(0);
	if (c->epoll_fd < 0) {
		perror("Error creating epoll handle");
		exit(EXIT_FAILURE);
	}

	/* FIXME: set up events for peer and console */
}

static void update_tcpr(struct chat *c)
{
	if (sendto(c->ctl_socket, "1\n", 2, 0, (struct sockaddr *)&c->ctl_address, sizeof(c->ctl_address)) < 0)
		perror("Error updating TCPR");
}

static void notify_tcpr_done_reading(struct chat *c)
{
	c->state->saved.done_reading = 1;
	update_tcpr(c);
}

static void notify_tcpr_done_writing(struct chat *c)
{
	c->state->saved.done_writing = 1;
}

static void handle_events(struct chat *c)
{
	/* FIXME: ferry data */

	/* FIXME: debugging */
	if (c->using_tcpr) {
		notify_tcpr_done_writing(c);
		notify_tcpr_done_reading(c);
	}
}

static void teardown_events(struct chat *c)
{
	close(c->epoll_fd);
}

static void teardown_tcpr(struct chat *c)
{
	if (!c->using_tcpr)
		return;
	teardown_state(c->state);
	teardown_ctl(c->ctl_socket);
}

static void teardown_connection(struct chat *c)
{
	if (close(c->peer_socket) < 0)
		perror("Closing connection");
}

int main(int argc, char **argv)
{
	struct chat c;

	handle_options(&c, argc, argv);

	setup_connection(&c);
	setup_tcpr(&c);
	setup_events(&c);

	handle_events(&c);

	teardown_events(&c);
	teardown_tcpr(&c);
	teardown_connection(&c);

	return EXIT_SUCCESS;
}
