#include <tcpr/types.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
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
static char *hard_address;

static struct sockaddr_in sockname;
static struct sockaddr_in peername;

static int discard;
static unsigned long generate;

static int checkpointing = 1;
static int verbose;

static int listen_sock = -1;
static int tcpr_sock = -1;
static int sock = -1;

struct tcpr_ip4 state;

static char send_buffer[16384];
static char receive_buffer[16384];
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
	fprintf(stderr, "  -r [HOST:]PORT  Recover for old HOST:PORT.\n");
	fprintf(stderr, "  -C              Bypass TCPR checkpointing.\n");
	fprintf(stderr, "  -d              Discard input.\n");
	fprintf(stderr, "  -g BYTES        Generate output.\n");
	fprintf(stderr, "  -v              Print connection statistics.\n");
	fprintf(stderr, "  -?              Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void split_address(char **host, char **port, char *address)
{
	char *c;

	c = strchr(address, ':');
	if (c) {
		*c++ = '\0';
		*host = address;
		*port = *c ? c : NULL;
		
	} else {
		*host = NULL;
		*port = address;
	}
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "b:c:t:r:Cdg:v?")) {
		case 'b':
			split_address(&bind_host, &bind_port, optarg);
			break;
		case 'c':
			split_address(&connect_host, &connect_port, optarg);
			break;
		case 't':
			split_address(&tcpr_host, &tcpr_port, optarg);
			using_tcpr = 1;
			break;
		case 'r':
			split_address(&recover_host, &recover_port, optarg);
			break;
		case 'C':
			checkpointing = 0;
			break;
		case 'd':
			discard = 1;
			break;
		case 'g':
			generate = atoi(optarg);
			user_eof = 1;
			break;
		case 'v':
			verbose++;
			break;
		case -1:
			return;
		default:
			print_help_and_exit(argv[0]);
		}

	if (!using_tcpr) {
		checkpointing = 0;
	}

	if (!recover_host)
		recover_host = bind_host;
	if (!recover_port)
		recover_port = bind_port;
	if (!bind_host)
		bind_host = recover_host;
	if (!bind_port)
		bind_port = recover_port;
}

static int resolve_address(struct sockaddr *name, char *host, char *port,
			   int socktype, int protocol)
{
	int err;
	struct addrinfo hints;
	struct addrinfo *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;

	err = getaddrinfo(host, port, &hints, &ai);
	if (err)
		return err;

	memcpy(name, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	return 0;
}

static int reify_addresses(struct sockaddr_in *self, struct sockaddr_in *peer)
{
	struct sockaddr_in actual;
	socklen_t socklen;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return -1;

	actual.sin_family = AF_INET;
	actual.sin_addr.s_addr = self->sin_addr.s_addr;
	actual.sin_port = 0;
	if (bind(s, (struct sockaddr *)&actual, sizeof(actual))) {
		close(s);
		return -1;
	}

	if (connect(s, (struct sockaddr *)peer, sizeof(*peer))) {
		close(s);
		return -1;
	}

	socklen = sizeof(actual);
	if (getsockname(s, (struct sockaddr *)&actual, &socklen)) {
		close(s);
		return -1;
	}

	close(s);
	self->sin_addr.s_addr = actual.sin_addr.s_addr;
	return 0;
}

static int connect_to_tcpr(const char *host, const char *port)
{
	int s;
	struct sockaddr_in name;

	if (resolve_address((struct sockaddr *)&name, host, port, SOCK_DGRAM, IPPROTO_UDP))
		return -1;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)&name, sizeof(name))) { 
		close(s);
		return -1;
	}

	return s;
}

static int get_tcpr_state(struct tcpr_ip4 *state, int tcprsock,
			  const char *application_host, const char *application_port,
			  const char *peer_host, const char *peer_port)
{
	memset(state, 0, sizeof(*state));
	state->hard_address = self->sin_addr.s_addr;
	state->peer_address = peer->sin_addr.s_addr;
	state->tcpr.hard.port = self->sin_port;
	state->tcpr.hard.peer.port = peer->sin_port;

	if (send(tcprsock, state, sizeof(*state), 0) < 0) {
		perror("Sending TCPR query");
		return -1;
	}

	if (recv(tcprsock, state, sizeof(*state), 0) < 0) {
		perror("Receiving TCPR state");
		return -1;
	}

	return 0;
}

static int connect_to_peer(const char *bind_host, const char *bind_port,
			   const char *connect_host, const char *connect_port,
			   const char *recover_host, const char *recover_port,
			   struct tcpr_ip4 *state, int tcprsock)
{
	int s;
	int yes = 1;
	struct sockaddr_in bind_address;
	struct sockaddr_in connect_address;
	struct sockaddr_in recover_address;
	socklen_t socklen;

	if (resolve_address((struct sockaddr *)&connect_address, connect_host, connect_port, SOCK_STREAM, IPPROTO_TCP))
		return -1;

	if (bind_host || bind_port) {
		if (resolve_address((struct sockaddr *)&bind_address, bind_host, bind_port, SOCK_STREAM, IPPROTO_TCP))
			return -1;
	} else {
		bind_address.sin_family = AF_INET;
		bind_address.sin_port = 0;
		bind_address.sin_addr.s_addr = INADDR_ANY;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0)
		return -1;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
		close(s);
		return -1;
	}

	if (bind(s, (struct sockaddr *)&bind_address, sizeof(bind_address))) {
		close(s);
		return -1;
	}

	socklen = sizeof(bind_address);
	if (getsockname(s, (struct sockaddr *)&bind_address, &socklen)) {
		close(s);
		return -1;
	}

	if (reify_addresses((struct sockaddr *)&bind_address, (struct sockaddr *)&connect_address)) {
		close(s);
		return -1;
	}

	if (recover_host || recover_port) {
		if (resolve_address((struct sockaddr *)&recover_address, recover_host, recover_port, SOCK_STREAM, IPPROTO_TCP)) {
			close(s);
			return -1;
		}
		if (!recover_address.sin_addr.s_addr)
			recover_address.sin_addr.s_addr = bind_address.sin_addr.s_addr;
		if (!recover_address.sin_port)
			recover_address.sin_port = bind_address.sin_port;
	} else {
		recover_address.sin_family = AF_INET;
		recover_address.sin_addr.s_addr = bind_address.sin_addr.s_addr;
		recover_address.sin_port = bind_address.sin_port;
	}

	if (state) {
		if (get_tcpr_state(state, tcprsock, &recover_address, &connect_address)) {
			close(s);
			return -1;
		}
		state->address = bind_address.sin_addr.s_addr;
		state->tcpr.port = bind_address.sin_port;
		if (send(tcprsock, state, sizeof(*state), 0) < 0) {
			close(s);
			return -1;
		}
	}

	if (connect(s, (struct sockaddr *)&connect_address, sizeof(connect_address))) {
		close(s);
		return -1;
	}

	if (get_tcpr_state(state, tcprsock, &recover_address, &connect_address)) {
		close(s);
		return -1;
	}

	return s;
}

static void print_direction_statistics(char *name, unsigned long total, struct timespec *end)
{
	double time_total;
	double throughput;

	time_total = (double)end->tv_sec - (double)start.tv_sec + ((double)end->tv_nsec - (double)start.tv_nsec) / 1e9;
	throughput = 8.0 * (double)total / time_total / 1e6;
	fprintf(stderr, "%s: %lu bytes, %.9lf seconds, %.9lf Mbps\n", name, total, time_total, throughput);
}

static void handle_events(void)
{
	fd_set rfds;
	fd_set wfds;
	ssize_t n;

	signal(SIGPIPE, SIG_IGN);

	if (!checkpointing) {
		state.tcpr.hard.done_reading = 1;
		send(tcpr_sock, &state, sizeof(state), 0);
	}

	if (clock_gettime(CLOCK_REALTIME, &start))
		perror("clock_gettime");
	while (!peer_eof || !user_eof || send_buffer_size
					|| receive_buffer_size
					|| generate > send_total) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (!peer_eof && receive_buffer_size < sizeof(receive_buffer))
			FD_SET(sock, &rfds);
		if (!user_eof && send_buffer_size < sizeof(send_buffer))
			FD_SET(0, &rfds);
		if (receive_buffer_size > 0)
			FD_SET(1, &wfds);
		if (send_buffer_size > 0 || generate > send_total)
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
				receive_total += n;
				if (!discard)
					receive_buffer_size += n;
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
			if (generate) {
				n = write(sock, send_buffer, generate < sizeof(send_buffer) ? generate : sizeof(send_buffer));
				if (n < 0) {
					perror("Writing to peer");
					exit(EXIT_FAILURE);
				}
				send_total += n;
			} else {
				n = write(sock, send_buffer, send_buffer_size);
				if (n < 0) {
					perror("Writing to peer");
					exit(EXIT_FAILURE);
				}
				send_buffer_size -= n;
				send_total += n;
				if (send_buffer_size > 0) {
					memmove(send_buffer, &send_buffer[n],
						send_buffer_size);
				}
			}
			if (user_eof && send_total >= generate) {
				if (tcpr_address) {
					state.tcpr.hard.done_writing = 1;
					send(tcpr_sock, &state, sizeof(state), 0);
				}
				shutdown(sock, SHUT_WR);
				if (clock_gettime(CLOCK_REALTIME, &send_end))
					perror("clock_gettime");
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

	if (verbose) {
		if (receive_total)
			print_direction_statistics("Received", receive_total, &receive_end);
		if (send_total)
			print_direction_statistics("Sent", send_total, &send_end);
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

int main(int argc, char **argv)
{
	handle_options(argc, argv);
	setup_tcpr_connection();
	setup_connection();
	handle_events();
	teardown();
	return EXIT_SUCCESS;
}
