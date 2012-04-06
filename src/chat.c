#include <tcpr/types.h>
#include <tcpr/module.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *internal_host = "127.0.0.3";
static const char *external_host = "127.0.0.2";
static const char *peer_host = "127.0.0.1";
static const char *peer_port = "9999";
static const char *port = "8888";

static int running_peer;
static int application_is_server;
static int using_tcpr = 1;
static int checkpointing = 1;

static int sock;
static int tcprfd;
struct tcpr tcpr;
struct tcpr_connection tcprc;

static char send_buffer[512];
static char receive_buffer[512];
static size_t send_buffer_size;
static size_t receive_buffer_size;
static int user_eof;
static int peer_eof;

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
			using_tcpr = 0;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup(void)
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
	struct sockaddr_in address;
	struct sockaddr_in peer_address;

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
		sock = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(peer_address);
		sock = accept(s, (struct sockaddr *)&peer_address, &addrlen);
		if (sock < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		close(s);
	}

	addrlen = sizeof(address);
	getsockname(sock, (struct sockaddr *)&address, &addrlen);

	if (using_tcpr) {
		tcprfd = open("/dev/tcpr", O_RDWR);
		if (tcprfd < 0) {
			perror("Opening TCPR handle");
			exit(EXIT_FAILURE);
		}
		tcprc.address = address.sin_addr.s_addr;
		tcprc.peer_address = peer_address.sin_addr.s_addr;
		tcprc.port = address.sin_port;
		tcprc.peer_port = peer_address.sin_port;
		if (ioctl(tcprfd, TCPR_ATTACH, &tcprc) < 0) {
			perror("Attaching to connection");
			exit(EXIT_FAILURE);
		}
		if (!checkpointing && ioctl(tcprfd, TCPR_DONE_READING) < 0) {
			perror("Shutting down input");
			exit(EXIT_FAILURE);
		}
	}
}

static void handle_events(void)
{
	fd_set rfds;
	fd_set wfds;
	ssize_t n;

	while (!peer_eof || !user_eof || send_buffer_size
					|| receive_buffer_size) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (!peer_eof && receive_buffer_size < sizeof(receive_buffer))
			FD_SET(sock, &rfds);
		if (!user_eof && send_buffer_size < sizeof(send_buffer))
			FD_SET(0, &rfds);
		if (receive_buffer_size > 0)
			FD_SET(1, &wfds);
		if (send_buffer_size > 0)
			FD_SET(sock, &wfds);
		if (select(sock + 1, &rfds, &wfds, NULL, NULL) < 0) {
			perror("Waiting for events");
			exit(EXIT_FAILURE);
		}

		if (FD_ISSET(sock, &rfds)) {
			n = read(sock, &receive_buffer[receive_buffer_size],
					sizeof(receive_buffer)
						- receive_buffer_size);
			if (n > 0) {
				if (using_tcpr && checkpointing && ioctl(tcprfd, TCPR_ACK, n) < 0) {
					perror("Acknowledging data");
					exit(EXIT_FAILURE);
				}
				receive_buffer_size += n;
			} else if (n < 0) {
				perror("Reading from peer");
				exit(EXIT_FAILURE);
			} else {
				if (using_tcpr && ioctl(tcprfd, TCPR_DONE_READING) < 0) {
					perror("Shutting down input");
					exit(EXIT_FAILURE);
				}
				shutdown(sock, SHUT_RD);
				peer_eof = 1;
			}
		}

		if (FD_ISSET(sock, &wfds)) {
			n = write(sock, send_buffer, send_buffer_size);
			if (n > 0) {
				send_buffer_size -= n;
				if (send_buffer_size > 0) {
					memmove(send_buffer, &send_buffer[n],
						send_buffer_size);
				} else if (user_eof) {
					if (using_tcpr && ioctl(tcprfd, TCPR_DONE_WRITING) < 0) {
						perror("Shutting down output");
						exit(EXIT_FAILURE);
					}
					shutdown(sock, SHUT_WR);
				}
			} else if (n < 0) {
				perror("Writing to peer");
				exit(EXIT_FAILURE);
			}
		}

		if (FD_ISSET(0, &rfds)) {
			n = read(0, &send_buffer[send_buffer_size],
					sizeof(send_buffer) - send_buffer_size);
			if (n > 0) {
				send_buffer_size += n;
			} else if (n < 0) {
				perror("Reading from user");
				exit(EXIT_FAILURE);
			} else {
				user_eof = 1;
				if (send_buffer_size == 0) {
					if (using_tcpr && ioctl(tcprfd, TCPR_DONE_WRITING) < 0) {
						perror("Shutting down output");
						exit(EXIT_FAILURE);
					}
					shutdown(sock, SHUT_WR);
				}
			}
		}

		if (FD_ISSET(1, &wfds)) {
			n = write(1, receive_buffer, receive_buffer_size);
			if (n > 0) {
				receive_buffer_size -= n;
				if (receive_buffer_size > 0)
					memmove(receive_buffer,
						&receive_buffer[n],
						receive_buffer_size);
			} else if (n < 0) {
				perror("Writing to user");
				exit(EXIT_FAILURE);
			}
		}
	}
}

static void teardown(void)
{
	if (using_tcpr) {
		if (ioctl(tcprfd, TCPR_WAIT) < 0) {
			perror("Waiting for connection to close");
			exit(EXIT_FAILURE);
		}
		if (close(tcprfd) < 0) {
			perror("Closing TCPR handle");
			exit(EXIT_FAILURE);
		}
	}
	if (close(sock) < 0)
		perror("Closing");
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup();
	handle_events();
	teardown();
	return EXIT_SUCCESS;
}
