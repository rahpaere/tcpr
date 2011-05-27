#include <tcpr/application.h>

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

struct flow {
	char buffer[512];
	ssize_t read;
	ssize_t written;
	int src;
	int dst;
	int is_open;
};

struct chat {
	const char *bind_host;
	const char *bind_port;
	const char *connect_host;
	const char *connect_port;
	int epoll_fd;
	int using_tcpr;
	int max_events;
	struct flow flow_to_peer;
	struct flow flow_to_user;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;
	struct tcpr_connection tcpr;
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
	c->max_events = 256;

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

		addrlen = sizeof(c->peer_address);
		getpeername(s, (struct sockaddr *)&c->peer_address, &addrlen);

		c->flow_to_peer.dst = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(c->peer_address);
		c->flow_to_peer.dst = accept(s, (struct sockaddr *)&c->peer_address, &addrlen);;
		if (c->flow_to_peer.dst < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}

		close(s);
	}

	addrlen = sizeof(c->address);
	getsockname(c->flow_to_peer.dst, (struct sockaddr *)&c->address, &addrlen);

	c->flow_to_user.src = dup(c->flow_to_peer.dst);
	c->flow_to_user.dst = 1;
	c->flow_to_user.is_open = 1;

	c->flow_to_peer.src = 0;
	c->flow_to_peer.is_open = 1;
}

static void setup_tcpr(struct chat *c)
{
	if (!c->using_tcpr)
		return;
	if (tcpr_setup_connection(&c->tcpr, c->flow_to_peer.dst) < 0) {
		perror("Error setting up TCPR");
		exit(EXIT_FAILURE);
	}
}

static void setup_events(struct chat *c)
{
	struct epoll_event event;

	c->epoll_fd = epoll_create1(0);
	if (c->epoll_fd < 0) {
		perror("Error creating epoll handle");
		exit(EXIT_FAILURE);
	}

	event.events = EPOLLIN;
	event.data.ptr = &c->flow_to_peer;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_peer.src, &event) < 0) {
		perror("Error adding peer input to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &c->flow_to_user;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_user.src, &event) < 0) {
		perror("Error adding user input to epoll");
		exit(EXIT_FAILURE);
	}

	event.events = 0;
	event.data.ptr = &c->flow_to_peer;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_peer.dst, &event) < 0) {
		perror("Error adding peer output to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &c->flow_to_user;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_user.dst, &event) < 0) {
		perror("Error adding user output to epoll");
		exit(EXIT_FAILURE);
	}
}

static void handle_close(struct flow *f, struct chat *c, struct epoll_event *e)
{
	f->is_open = 0;
	if (f == &c->flow_to_peer) {
		if (c->using_tcpr)
			tcpr_done_writing(&c->tcpr);
		shutdown(f->dst, SHUT_WR);
	} else {
		if (c->using_tcpr)
			tcpr_done_reading(&c->tcpr);
		shutdown(f->src, SHUT_RD);
	}
	e->events = 0;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
		perror("Error disabling input event");
		exit(EXIT_FAILURE);
	}
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
		perror("Error disabling output event");
		exit(EXIT_FAILURE);
	}
}

static void handle_input(struct flow *f, struct chat *c, struct epoll_event *e)
{
	f->written = 0;
	f->read = read(f->src, f->buffer, sizeof(f->buffer));
	if (f->read < 0) {
		perror("Reading input");
		exit(EXIT_FAILURE);
	} else if (f->read == 0) {
		handle_close(f, c, e);
		return;
	}

	if (f == &c->flow_to_user && c->using_tcpr)
		tcpr_consume(&c->tcpr, f->read);
	e->events = 0;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
		perror("Error disabling input event");
		exit(EXIT_FAILURE);
	}
	e->events = EPOLLOUT;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
		perror("Error enabling output event");
		exit(EXIT_FAILURE);
	}
}

static void handle_output(struct flow *f, struct chat *c, struct epoll_event *e)
{
	ssize_t written;

	written = write(f->dst, &f->buffer[f->written], f->read - f->written);
	if (written < 0) {
		perror("Writing output");
		exit(EXIT_FAILURE);
	}

	f->written += written;
	if (f->written == f->read) {
		e->events = 0;
		if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
			perror("Error disabling output event");
			exit(EXIT_FAILURE);
		}
		e->events = EPOLLIN;
		if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
			perror("Error enabling input event");
			exit(EXIT_FAILURE);
		}
	}
}

static void handle_events(struct chat *c)
{
	int i;
	int n;
	struct epoll_event e[c->max_events];

	while (c->flow_to_peer.is_open || c->flow_to_user.is_open) {
		n = epoll_wait(c->epoll_fd, e, c->max_events, -1);
		if (n < 0) {
			perror("Error waiting for events");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < n; i++) {
			if (e[i].events & EPOLLIN)
				handle_input(e[i].data.ptr, c, &e[i]);
			else if (e[i].events & EPOLLOUT)
				handle_output(e[i].data.ptr, c, &e[i]);
		}
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
	tcpr_teardown_connection(&c->tcpr);
}

static void teardown_connection(struct chat *c)
{
	if (close(c->flow_to_peer.dst) < 0)
		perror("Closing connection");
	if (close(c->flow_to_user.src) < 0)
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
