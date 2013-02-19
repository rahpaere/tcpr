#include <tcpr/types.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

struct client {
	int sock;
	struct tcpr_ip4 state;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;
	char buffer[512];
	size_t size;
	int shut;
};

static const char state_path_format[] = "/var/tmp/tcpr-bridge-%s.state";

static char *tcpr_address;
static char *bind_address;

static int checkpointing = 1;
static int recovering;

static struct client *clients;

static int tcpr_sock;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Bridge data across client connections, using TCPR.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b [HOST]:PORT  Bind to HOST:PORT.\n");
	fprintf(stderr, "  -t [HOST]:PORT  Connect to TCPR at HOST:PORT.\n");
	fprintf(stderr, "  -C              Bypass checkpointed acknowledgments.\n");
	fprintf(stderr, "  -?              Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "b:t:C?")) {
		case 'b':
			bind_address = optarg;
			break;
		case 't':
			tcpr_address = optarg;
			break;
		case 'C':
			checkpointing = 0;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
	if (!tcpr_address || !bind_address)
		print_help_and_exit(argv[0]);
}

static void setup(void)
{
	char path[sizeof(state_path_format) + strlen(bind_address)];
	int fd;

	sprintf(path, state_path_format, bind_address);
	
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fd = open(path, O_RDWR);
		if (fd < 0) {
			perror("Opening state");
			exit(EXIT_FAILURE);
		}
		recovering = 1;
	} else if (ftruncate(fd, 2 * sizeof(clients[0])) < 0) {
		perror("Resizing state");
		exit(EXIT_FAILURE);
	}

	clients = mmap(NULL, 2 * sizeof(clients[0]), PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (clients == MAP_FAILED) {
		perror("Mapping state");
		exit(EXIT_FAILURE);
	}
	close(fd);
}

static void setup_connections(void)
{
	char *host;
	char *port;
	int err;
	int s;
	int yes = 1;
	socklen_t addrlen;
	struct addrinfo *ai;
	struct addrinfo hints;
	int i;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("Setting SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}

	port = strchr(bind_address, ':');
	if (port) {
		host = bind_address;
		*port++ = '\0';
	} else {
		port = bind_address;
		host = NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	err = getaddrinfo(host, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving bind: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Binding");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);
	if (listen(s, 1) < 0) {
		perror("Listening");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < 2; ++i) {
		addrlen = sizeof(clients[i].peer_address);
		clients[i].sock = accept(s, (struct sockaddr *)&clients[i].peer_address, &addrlen);
		if (clients[i].sock < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		addrlen = sizeof(clients[i].address);
		getsockname(clients[i].sock, (struct sockaddr *)&clients[i].address, &addrlen);
	}

	close(s);
}

static void recover_connections(void)
{
	int yes = 1;
	int i;

	for (i = 0; i < 2; ++i) {
		clients[i].sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (clients[i].sock < 0) {
			perror("Creating socket");
			exit(EXIT_FAILURE);
		}
		if (setsockopt(clients[i].sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
			perror("Setting SO_REUSEADDR");
			exit(EXIT_FAILURE);
		}
		if (bind(clients[i].sock, (struct sockaddr *)&clients[i].address,
					sizeof(clients[i].address)) < 0) {
			perror("Binding");
			exit(EXIT_FAILURE);
		}
		if (connect(clients[i].sock, (struct sockaddr *)&clients[i].peer_address,
					sizeof(clients[i].peer_address)) < 0) {
			perror("Connecting");
			exit(EXIT_FAILURE);
		}
	}
}

static void setup_tcpr(void)
{
	char *host;
	char *port;
	int err;
	int s;
	int i;
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

	for (i = 0; i < 2; i++) {
		clients[i].state.hard_address = clients[i].address.sin_addr.s_addr;
		clients[i].state.peer_address = clients[i].peer_address.sin_addr.s_addr;
		clients[i].state.tcpr.hard.port = clients[i].address.sin_port;
		clients[i].state.tcpr.hard.peer.port = clients[i].peer_address.sin_port;
		clients[i].state.tcpr.port = 0;

		send(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);
		recv(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);

		if (!checkpointing) {
			clients[i].state.tcpr.hard.done_reading = 1;
			send(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);
		}
	}
}

static void handle_events(void)
{
	fd_set rfds;
	fd_set wfds;
	ssize_t n;
	int i;
	int maxfd;

	maxfd = clients[0].sock > clients[1].sock ? clients[0].sock : clients[1].sock;
	while (!clients[0].shut || !clients[1].shut || clients[0].size || clients[1].size) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		for (i = 0; i < 2; ++i) {
			if (!clients[i].shut && clients[1 - i].size < sizeof(clients[1 - i].buffer))
				FD_SET(clients[i].sock, &rfds);
			if (clients[i].size)
				FD_SET(clients[i].sock, &wfds);
		}
		if (select(maxfd + 1, &rfds, &wfds, NULL, NULL) < 0) {
			perror("Waiting for events");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < 2; ++i) {
			if (FD_ISSET(clients[i].sock, &rfds)) {
				n = read(clients[i].sock, &clients[1 - i].buffer[clients[1 - i].size], sizeof(clients[1 - i].buffer) - clients[1 - i].size);
				if (n > 0) {
					if (checkpointing) {
						clients[i].state.tcpr.hard.ack = htonl(ntohl(clients[i].state.tcpr.hard.ack) + n);
						send(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);
					}
					clients[1 - i].size += n;
				} else if (n < 0) {
					perror("Reading");
					exit(EXIT_FAILURE);
				} else {
					clients[i].state.tcpr.hard.done_reading = 1;
					send(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);
					shutdown(clients[i].sock, SHUT_RD);
					clients[i].shut = 1;
					if (clients[1 - i].size == 0) {
						clients[1 - i].state.tcpr.hard.done_writing = 1;
						send(tcpr_sock, &clients[1 - i].state, sizeof(clients[1 - i].state), 0);
						shutdown(clients[1 - i].sock, SHUT_WR);
					}
				}
			}

			if (FD_ISSET(clients[i].sock, &wfds)) {
				n = write(clients[i].sock, clients[i].buffer, clients[i].size);
				if (n > 0) {
					clients[i].size -= n;
					if (clients[i].size > 0) {
						memmove(clients[i].buffer, &clients[i].buffer[n], clients[i].size);
					} else if (clients[1 - i].shut) {
						clients[i].state.tcpr.hard.done_writing = 1;
						send(tcpr_sock, &clients[i].state, sizeof(clients[i].state), 0);
						shutdown(clients[i].sock, SHUT_WR);
					}
				} else if (n < 0) {
					perror("Writing to peer");
					exit(EXIT_FAILURE);
				}
			}
		}
	}
}

static void teardown(void)
{
	char path[sizeof(state_path_format) + strlen(bind_address)];
	int i;

	for (i = 0; i < 2; ++i) {
		if (close(clients[i].sock) < 0) {
			perror("Closing");
			exit(EXIT_FAILURE);
		}
	}

	close(tcpr_sock);

	sprintf(path, state_path_format, bind_address);
	unlink(path);

	munmap(clients, 2 * sizeof(clients[0]));
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup();
	if (recovering)
		recover_connections();
	else
		setup_connections();
	setup_tcpr();
	handle_events();
	teardown();
	return EXIT_SUCCESS;
}
