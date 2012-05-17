#include <tcpr/types.h>

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
#include <time.h>
#include <unistd.h>

static char *tcpr_address;
static char *bind_address;
static char *connect_address;

static struct sockaddr_in sockname;
static struct sockaddr_in peername;

static int checkpointing = 1;
static int verbose;

static int listen_sock = -1;
static int tcpr_sock = -1;
static int sock = -1;

struct tcpr_ip4 state;

static char send_buffer[512];
static char receive_buffer[512];
static size_t send_buffer_size;
static size_t receive_buffer_size;
static int user_eof;
static int peer_eof;
static unsigned long send_total;
static unsigned long receive_total;
static struct timespec start;
static struct timespec receive_end;
static struct timespec send_end;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Forward standard input and output through a TCP "
		"connection, using TCPR.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b [HOST:]PORT  Bind to HOST:PORT.\n");
	fprintf(stderr, "  -c [HOST:]PORT  Connect to HOST:PORT.\n");
	fprintf(stderr, "  -t [HOST:]PORT  Connect to TCPR at HOST:PORT.\n");
	fprintf(stderr, "  -C              Bypass TCPR checkpointing.\n");
	fprintf(stderr, "  -v              Print connection statistics.\n");
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
		case 'C':
			checkpointing = 0;
			break;
		case 'v':
			verbose = 1;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}
}

static void setup_connection(void)
{
	char *host;
	char *port;
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

	if (bind_address) {
		port = strchr(bind_address, ':');
		if (port) {
			host = bind_address;
			*port++ = '\0';
		} else {
			port = bind_address;
			host = NULL;
		}

		if (!connect_address)
			hints.ai_flags |= AI_PASSIVE;
		err = getaddrinfo(host, port, &hints, &ai);
		if (err) {
			fprintf(stderr, "Resolving \"%s\": %s\n", bind_address, gai_strerror(err));
			exit(EXIT_FAILURE);
		}
		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Binding");
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(ai);

		if (!connect_address) {
			if (listen(s, 16) < 0) {
				perror("Listening");
				exit(EXIT_FAILURE);
			}
			listen_sock = s;
			addrlen = sizeof(peername);
			s = accept(listen_sock, (struct sockaddr *)&peername, &addrlen);
			if (s < 0) {
				perror("Accepting");
				exit(EXIT_FAILURE);
			}

			addrlen = sizeof(sockname);
			getsockname(s, (struct sockaddr *)&sockname, &addrlen);
			sock = s;
			return;
		}
	}

	port = strchr(connect_address, ':');
	if (port) {
		host = connect_address;
		*port++ = '\0';
	} else {
		port = connect_address;
		host = NULL;
	}

	err = getaddrinfo(host, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "Resolving \"%s\": %s\n", connect_address, gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	while (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Connecting");
		if (errno != ECONNREFUSED)
			exit(EXIT_FAILURE);
		sleep(2);
	}
	freeaddrinfo(ai);

	addrlen = sizeof(peername);
	getpeername(s, (struct sockaddr *)&peername, &addrlen);

	addrlen = sizeof(sockname);
	getsockname(s, (struct sockaddr *)&sockname, &addrlen);

	sock = s;
}

static void setup_tcpr(void)
{
	char *host;
	char *port;
	int err;
	int s;
	struct addrinfo *ai;
	struct addrinfo hints;

	if (!tcpr_address) {
		checkpointing = 0;
		return;
	}

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

	state.address = sockname.sin_addr.s_addr;
	state.peer_address = peername.sin_addr.s_addr;
	state.tcpr.hard.port = sockname.sin_port;
	state.tcpr.hard.peer.port = peername.sin_port;

	send(tcpr_sock, &state, sizeof(state), 0);
	recv(tcpr_sock, &state, sizeof(state), 0);

	if (!checkpointing) {
		state.tcpr.hard.done_reading = 1;
		send(tcpr_sock, &state, sizeof(state), 0);
	}
}

static void handle_events(void)
{
	fd_set rfds;
	fd_set wfds;
	ssize_t n;

	if (clock_gettime(CLOCK_REALTIME, &start))
		perror("clock_gettime");
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
				if (checkpointing) {
					state.tcpr.hard.ack = htonl(ntohl(state.tcpr.hard.ack) + n);
					send(tcpr_sock, &state, sizeof(state), 0);
				}
				receive_buffer_size += n;
				receive_total += n;
			} else if (n < 0) {
				perror("Reading from peer");
				exit(EXIT_FAILURE);
			} else {
				if (tcpr_address) {
					state.tcpr.hard.done_reading = 1;
					send(tcpr_sock, &state, sizeof(state), 0);
				}
				shutdown(sock, SHUT_RD);
				peer_eof = 1;
				if (clock_gettime(CLOCK_REALTIME, &receive_end))
					perror("clock_gettime");
			}
		}

		if (FD_ISSET(sock, &wfds)) {
			n = write(sock, send_buffer, send_buffer_size);
			if (n > 0) {
				send_buffer_size -= n;
				send_total += n;
				if (send_buffer_size > 0) {
					memmove(send_buffer, &send_buffer[n],
						send_buffer_size);
				} else if (user_eof) {
					if (tcpr_address) {
						state.tcpr.hard.done_writing = 1;
						send(tcpr_sock, &state, sizeof(state), 0);
					}
					shutdown(sock, SHUT_WR);
					if (clock_gettime(CLOCK_REALTIME, &send_end))
						perror("clock_gettime");
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
					if (tcpr_address) {
						state.tcpr.hard.done_writing = 1;
						send(tcpr_sock, &state, sizeof(state), 0);
					}
					shutdown(sock, SHUT_WR);
					if (clock_gettime(CLOCK_REALTIME, &send_end))
						perror("clock_gettime");
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
	if (tcpr_sock != -1 && close(tcpr_sock) < 0)
		perror("Closing TCPR socket");
	if (listen_sock != -1 && close(listen_sock) < 0)
		perror("Closing listening socket");
	if (close(sock) < 0)
		perror("Closing");
}

static void print_direction_statistics(char *name, unsigned long total, struct timespec *end)
{
	double time_total;
	double throughput;

	time_total = (double)end->tv_sec - (double)start.tv_sec + ((double)end->tv_nsec - (double)start.tv_nsec) / 1e9;
	throughput = (double)total / time_total;
	fprintf(stderr, "%s: %lu bytes, %.9lf seconds, %.9lf bytes / second\n", name, total, time_total, throughput);
}

static void print_statistics(void)
{
	if (!verbose)
		return;
	if (receive_total)
		print_direction_statistics("Received", receive_total, &receive_end);
	if (send_total)
		print_direction_statistics("Sent", send_total, &send_end);
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup_connection();
	setup_tcpr();
	handle_events();
	teardown();
	print_statistics();
	return EXIT_SUCCESS;
}
