#include <tcpr/application.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
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

static const char *internal_host = "10.0.1.1";
static const char *external_host = "10.0.0.1";
static const char *peer_host = "10.0.0.2";
static const char *peer_port = "9999";
static const char *port = "8888";
static int running_peer;
static int application_is_server;
static int using_tcpr = 1;
static int checkpointing = 1;
static int epoll_fd;
static struct flow flow_to_peer;
static struct flow flow_to_user;
static struct sockaddr_in address;
static struct sockaddr_in peer_address;
static struct tcpr_connection tcpr;

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

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "i:e:a:h:p:sCTP?")) {
		case 'i':
			internal_host = optarg;
			break;
		case 'e':
			external_host = optarg;
			break;
		case 'a':
			port = optarg;
			break;
		case 'h':
			peer_host = optarg;
			break;
		case 'p':
			peer_port = optarg;
			break;
		case 's':
			application_is_server = 1;
			break;
		case 'C':
			checkpointing = 0;
			break;
		case 'T':
			using_tcpr = 0;
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

static void setup_connection(void)
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

	if (running_peer) {
		bind_host = peer_host;
		bind_port = peer_port;
		if (application_is_server) {
			connect_host = external_host;
			connect_port = port;
		}
	} else {
		bind_host = using_tcpr ? internal_host : external_host;
		bind_port = port;
		if (!application_is_server) {
			connect_host = peer_host;
			connect_port = peer_port;
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

		addrlen = sizeof(peer_address);
		getpeername(s, (struct sockaddr *)&peer_address, &addrlen);
		flow_to_peer.dst = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(peer_address);
		flow_to_peer.dst =
		    accept(s, (struct sockaddr *)&peer_address, &addrlen);
		if (flow_to_peer.dst < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		close(s);
	}

	addrlen = sizeof(address);
	getsockname(flow_to_peer.dst, (struct sockaddr *)&address,
		    &addrlen);

	flow_to_user.src = dup(flow_to_peer.dst);
	flow_to_user.dst = 1;
	flow_to_user.is_open = 1;

	flow_to_peer.src = 0;
	flow_to_peer.is_open = 1;

	if (!running_peer && using_tcpr) {
		if (tcpr_setup_connection(&tcpr, peer_address.sin_addr.s_addr, peer_address.sin_port, address.sin_port, 0) < 0) {
			perror("Opening state");
			exit(EXIT_FAILURE);
		}
		if (!checkpointing)
			tcpr_shutdown_input(&tcpr);
	}
}

static void setup_events(void)
{
	struct epoll_event event;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("Error creating epoll handle");
		exit(EXIT_FAILURE);
	}

	event.events = EPOLLIN;
	event.data.ptr = &flow_to_peer;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, flow_to_peer.src, &event) <
	    0) {
		perror("Error adding peer input to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &flow_to_user;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, flow_to_user.src, &event) <
	    0) {
		perror("Error adding user input to epoll");
		exit(EXIT_FAILURE);
	}

	event.events = 0;
	event.data.ptr = &flow_to_peer;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, flow_to_peer.dst, &event) <
	    0) {
		perror("Error adding peer output to epoll");
		exit(EXIT_FAILURE);
	}
	event.data.ptr = &flow_to_user;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, flow_to_user.dst, &event) <
	    0) {
		perror("Error adding user output to epoll");
		exit(EXIT_FAILURE);
	}
}

static void handle_close(struct flow *f, struct epoll_event *e)
{
	f->is_open = 0;
	if (f == &flow_to_peer) {
		if (!running_peer && using_tcpr)
			tcpr_shutdown_output(&tcpr);
		shutdown(f->dst, SHUT_WR);
	} else {
		if (!running_peer && using_tcpr && checkpointing)
			tcpr_shutdown_input(&tcpr);
		shutdown(f->src, SHUT_RD);
	}
	e->events = 0;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
		perror("Error disabling input event");
		exit(EXIT_FAILURE);
	}
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
		perror("Error disabling output event");
		exit(EXIT_FAILURE);
	}
}

static void handle_input(struct flow *f, struct epoll_event *e)
{
	f->written = 0;
	f->read = read(f->src, f->buffer, sizeof(f->buffer));
	if (f->read < 0) {
		perror("Reading input");
		exit(EXIT_FAILURE);
	} else if (f->read == 0) {
		handle_close(f, e);
		return;
	}

	if (f == &flow_to_user && !running_peer && using_tcpr)
		tcpr_checkpoint_input(&tcpr, f->read);
	e->events = 0;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
		perror("Error disabling input event");
		exit(EXIT_FAILURE);
	}
	e->events = EPOLLOUT;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
		perror("Error enabling output event");
		exit(EXIT_FAILURE);
	}
}

static void handle_output(struct flow *f, struct epoll_event *e)
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
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->dst, e) < 0) {
			perror("Error disabling output event");
			exit(EXIT_FAILURE);
		}
		e->events = EPOLLIN;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, f->src, e) < 0) {
			perror("Error enabling input event");
			exit(EXIT_FAILURE);
		}
	}
}

static void handle_events(void)
{
	int i;
	int n;
	struct epoll_event e[MAX_EVENTS];

	while (flow_to_peer.is_open || flow_to_user.is_open) {
		n = epoll_wait(epoll_fd, e, MAX_EVENTS, -1);
		if (n < 0) {
			perror("Error waiting for events");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < n; i++) {
			if (e[i].events & EPOLLIN)
				handle_input(e[i].data.ptr, &e[i]);
			else if (e[i].events & EPOLLOUT)
				handle_output(e[i].data.ptr, &e[i]);
		}
	}
}

static void teardown_events(void)
{
	close(epoll_fd);
}

static void teardown_connection(void)
{
	if (!running_peer && using_tcpr) {
		tcpr_wait(&tcpr);
		tcpr_teardown_connection(&tcpr);
	}
	if (close(flow_to_peer.dst) < 0)
		perror("Closing connection");
	if (close(flow_to_user.src) < 0)
		perror("Closing connection");
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);

	setup_connection();
	setup_events();

	handle_events();

	teardown_events();
	teardown_connection();

	return EXIT_SUCCESS;
}
