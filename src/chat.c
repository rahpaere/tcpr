#include <tcpr/application.h>

#include <arpa/inet.h>
#include <errno.h>
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

#define MAX_EVENTS 256

struct flow {
	char buffer[512];
	ssize_t read;
	ssize_t written;
	int src;
	int dst;
	int is_open;
};

struct chat {
	const char *internal_host;
	const char *external_host;
	const char *peer_host;
	const char *peer_port;
	const char *port;
	int running_peer;
	int application_is_server;
	int using_tcpr;
	int checkpointing;
	int epoll_fd;
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
	fprintf(stderr, "Forward standard input and output through a TCP "
		"connection, using TCPR.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -i HOST  "
		"Internally, the application is bound to HOST.\n");
	fprintf(stderr, "  -e HOST  "
		"Externally, the application is bound to HOST.\n");
	fprintf(stderr, "  -a PORT  The application is bound to PORT.\n");
	fprintf(stderr, "  -h HOST  The peer is bound to HOST.\n");
	fprintf(stderr, "  -p PORT  The peer is bound to PORT.\n");
	fprintf(stderr, "  -s       The application is the TCP server.\n");
	fprintf(stderr, "  -C       Bypass checkpointed acknowledgments.\n");
	fprintf(stderr, "  -T       Do not use TCPR.\n");
	fprintf(stderr, "  -P       Run as the peer.\n");
	fprintf(stderr, "  -?       Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(struct chat *c, int argc, char **argv)
{
	int o;

	c->internal_host = "127.0.0.2";
	c->external_host = "127.0.0.1";
	c->port = "8888";
	c->peer_host = "127.0.0.1";
	c->peer_port = "9999";
	c->application_is_server = 0;
	c->checkpointing = 1;
	c->using_tcpr = 1;
	c->running_peer = 0;

	while ((o = getopt(argc, argv, "i:e:a:h:p:sCTP?")) != -1)
		switch (o) {
		case 'i':
			c->internal_host = optarg;
			break;
		case 'e':
			c->external_host = optarg;
			break;
		case 'a':
			c->port = optarg;
			break;
		case 'h':
			c->peer_host = optarg;
			break;
		case 'p':
			c->peer_port = optarg;
			break;
		case 's':
			c->application_is_server = 1;
			break;
		case 'C':
			c->checkpointing = 0;
			break;
		case 'T':
			c->using_tcpr = 0;
			break;
		case 'P':
			c->running_peer = 1;
			break;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup_connection(struct chat *c)
{
	const char *bind_host;
	const char *bind_port;
	const char *connect_host = NULL;
	const char *connect_port = NULL;
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

	if (c->running_peer) {
		bind_host = c->peer_host;
		bind_port = c->peer_port;
		if (c->application_is_server) {
			connect_host = c->external_host;
			connect_port = c->port;
		}
	} else {
		bind_host = c->using_tcpr ? c->internal_host : c->external_host;
		bind_port = c->port;
		if (!c->application_is_server) {
			connect_host = c->peer_host;
			connect_port = c->peer_port;
		}
	}

	if (!connect_port)
		hints.ai_flags |= AI_PASSIVE;
	err = getaddrinfo(bind_host, bind_port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving bind: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Binding");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);

	if (connect_port) {
		hints.ai_flags = 0;
		err = getaddrinfo(connect_host, connect_port, &hints, &ai);
		if (err) {
			fprintf(stderr, "Resolving: %s\n", gai_strerror(err));
			exit(EXIT_FAILURE);
		}
		while (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Connecting");
			if (errno != ECONNREFUSED)
				exit(EXIT_FAILURE);
			sleep(2);
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
		c->flow_to_peer.dst =
		    accept(s, (struct sockaddr *)&c->peer_address, &addrlen);
		if (c->flow_to_peer.dst < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		close(s);
	}

	addrlen = sizeof(c->address);
	getsockname(c->flow_to_peer.dst, (struct sockaddr *)&c->address,
		    &addrlen);

	c->flow_to_user.src = dup(c->flow_to_peer.dst);
	c->flow_to_user.dst = 1;
	c->flow_to_user.is_open = 1;

	c->flow_to_peer.src = 0;
	c->flow_to_peer.is_open = 1;

	if (!c->running_peer && c->using_tcpr) {
		if (tcpr_setup_connection(&c->tcpr, c->peer_address.sin_addr.s_addr, c->peer_address.sin_port, c->address.sin_port, 0) < 0) {
			perror("Opening state");
			exit(EXIT_FAILURE);
		}
		if (!c->checkpointing)
			tcpr_shutdown_input(&c->tcpr);
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
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_peer.src, &event) <
	    0) {
		perror("Error adding peer input to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &c->flow_to_user;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_user.src, &event) <
	    0) {
		perror("Error adding user input to epoll");
		exit(EXIT_FAILURE);
	}

	event.events = 0;
	event.data.ptr = &c->flow_to_peer;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_peer.dst, &event) <
	    0) {
		perror("Error adding peer output to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &c->flow_to_user;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->flow_to_user.dst, &event) <
	    0) {
		perror("Error adding user output to epoll");
		exit(EXIT_FAILURE);
	}
}

static void handle_close(struct flow *f, struct chat *c, struct epoll_event *e)
{
	f->is_open = 0;
	if (f == &c->flow_to_peer) {
		if (!c->running_peer && c->using_tcpr)
			tcpr_shutdown_output(&c->tcpr);
		shutdown(f->dst, SHUT_WR);
	} else {
		if (!c->running_peer && c->using_tcpr && c->checkpointing)
			tcpr_shutdown_input(&c->tcpr);
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

	if (f == &c->flow_to_user && !c->running_peer && c->using_tcpr)
		tcpr_checkpoint_input(&c->tcpr, f->read);
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
	struct epoll_event e[MAX_EVENTS];

	while (c->flow_to_peer.is_open || c->flow_to_user.is_open) {
		n = epoll_wait(c->epoll_fd, e, MAX_EVENTS, -1);
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

static void teardown_connection(struct chat *c)
{
	if (!c->running_peer && c->using_tcpr) {
		tcpr_wait(&c->tcpr);
		tcpr_teardown_connection(&c->tcpr);
	}
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
	setup_events(&c);

	handle_events(&c);

	teardown_events(&c);
	teardown_connection(&c);

	return EXIT_SUCCESS;
}
