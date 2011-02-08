#include "tcpr.h"

#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

static struct update *state;
static int data_socket;
static int update_socket;
static struct timespec timestamp;
static pthread_mutex_t flags_lock;
static pthread_cond_t state_ready;

static void message(const char *s)
{
	fprintf(stderr, "%lf %s\n", (double)timestamp.tv_sec
		+ (double)timestamp.tv_nsec / 1000000000.0, s);
}

static void message_now(const char *s)
{
	clock_gettime(CLOCK_REALTIME, &timestamp);
	message(s);
}

static void split_address(char *address, const char **host, const char **port)
{
	char *tmp = strrchr(address, ':');
	if (tmp) {
		*tmp = '\0';
		*host = address;
		*port = tmp + 1;
	} else {
		*host = NULL;
		*port = address;
	}
	if (**port == '\0')
		*port = NULL;
	if (**host == '\0')
		*host = NULL;
}

static void setup_state(const char *shm)
{
	int fd;

	message_now("Initializing persistent state.");

	fd = shm_open(shm, O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		perror("Opening persistent state");
		exit(EXIT_FAILURE);
	}
	if (ftruncate(fd, sizeof(*state)) < 0) {
		perror("Resizing persistent state");
		exit(EXIT_FAILURE);
	}
	state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (state == MAP_FAILED) {
		perror("Mapping persistent state");
		exit(EXIT_FAILURE);
	}
	close(fd);

	pthread_mutex_init(&flags_lock, NULL);
	pthread_cond_init(&state_ready, NULL);
}

static void setup_update_connection(const char *internal_host,
					const char *internal_port,
					const char *external_host,
					const char *external_port)
{
	int ret;
	struct addrinfo *ai;
	struct addrinfo hints;

	message_now("Establishing update connection.");

	update_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (update_socket < 0) {
		perror("Creating update socket");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	ret = getaddrinfo(internal_host, internal_port, &hints, &ai);
	if (ret) {
		fprintf(stderr, "Resolving internal address: %s\n",
				gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (bind(update_socket, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Binding update socket");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);

	ret = getaddrinfo(external_host, external_port, &hints, &ai);
	if (ret) {
		fprintf(stderr, "Resolving external address: %s\n",
				gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (connect(update_socket, ai->ai_addr, ai->ai_addrlen) < 0) {
		perror("Connecting update socket");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(ai);
}

static void setup_connection(const char *listen_host, const char *listen_port,
				const char *host, const char *port)
{
	int ret;
	int s;
	int yes = 1;
	struct addrinfo *ai;
	struct addrinfo hints;

	if (port)
		message_now("Connecting to peer.");
	else
		message_now("Waiting for peer to connect.");

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
	if (setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &yes, sizeof(yes)) < 0) {
		perror("Setting TCP_QUICKACK");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (listen_host || listen_port) {
		hints.ai_flags = (port ? 0 : AI_PASSIVE);
		ret = getaddrinfo(listen_host, listen_port, &hints, &ai);
		if (ret) {
			fprintf(stderr, "Resolving bind address: %s\n",
					gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Binding");
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(ai);
	}

	if (port) {
		hints.ai_flags = 0;
		ret = getaddrinfo(host, port, &hints, &ai);
		if (ret) {
			fprintf(stderr, "Resolving peer address: %s\n",
					gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Connecting");
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(ai);
		data_socket = s;
	} else {
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}
		data_socket = accept(s, NULL, NULL);
		if (data_socket < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		close(s);
	}

	message_now("Connected.");
}

static void recover_connection(const char *listen_host, const char *listen_port)
{
	int yes = 1;
	int ret;
	struct sockaddr_in addr;
	struct addrinfo *ai;
	struct addrinfo hints;

	message_now("Recovering connection.");

	data_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (data_socket < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR,
			&yes, sizeof(yes)) < 0) {
		perror("Setting socket option");
		exit(EXIT_FAILURE);
	}

	if (listen_host || listen_port) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		ret = getaddrinfo(listen_host, listen_port, &hints, &ai);
		if (ret) {
			fprintf(stderr, "Resolving bind address: %s\n",
					gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		if (bind(data_socket, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Binding");
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(ai);
	} else {
		addr.sin_family = AF_INET;
		addr.sin_port = state->tcpr.port;
		addr.sin_addr.s_addr = state->address;
		if (bind(data_socket, (struct sockaddr *)&addr,
				sizeof(addr)) < 0) {
			perror("Binding");
			exit(EXIT_FAILURE);
		}
	}

	addr.sin_family = AF_INET;
	addr.sin_port = state->tcpr.peer_port;
	addr.sin_addr.s_addr = state->peer_address;
	if (connect(data_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Connecting");
		exit(EXIT_FAILURE);
	}

	message_now("Connected.");
}

static void *read_from_peer(void *arg)
{
	char buf[1024];
	ssize_t bytes;
	ssize_t sent;
	ssize_t size;

	(void)arg;

	pthread_mutex_lock(&flags_lock);
	while (!state->tcpr.flags)
		pthread_cond_wait(&state_ready, &flags_lock);
	pthread_mutex_unlock(&flags_lock);

	while ((size = read(data_socket, buf, sizeof(buf))) > 0) {
		for (sent = 0; sent < size; sent += bytes) {
			message_now("Received data.");
			bytes = write(1, &buf[sent], size - sent);
			if (bytes < 0) {
				perror("Writing to user");
				exit(EXIT_FAILURE);
			}
			if (update_socket) {
				state->tcpr.ack = htonl(ntohl(state->tcpr.ack)
								+ bytes);
				if (write(update_socket, state,
						sizeof(*state)) < 0) {
					perror("Updating acknowledgment");
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	if (size < 0) {
		perror("Reading from peer");
		exit(EXIT_FAILURE);
	}
	message_now("Done reading.");
	if (update_socket) {
		pthread_mutex_lock(&flags_lock);
		state->tcpr.flags |= TCPR_DONE_READING;
		pthread_mutex_unlock(&flags_lock);
		if (write(update_socket, state, sizeof(*state)) < 0) {
			perror("Sending final acknowledgment");
			exit(EXIT_FAILURE);
		}
	}
	return NULL;
}

static void *send_to_peer(void *arg)
{
	char buf[1024];
	ssize_t bytes;
	ssize_t sent;
	ssize_t size;

	(void)arg;

	pthread_mutex_lock(&flags_lock);
	while (!state->tcpr.flags)
		pthread_cond_wait(&state_ready, &flags_lock);
	pthread_mutex_unlock(&flags_lock);

	while ((size = read(0, buf, sizeof(buf))) > 0)
		for (sent = 0; sent < size; sent += bytes) {
			message_now("Sending data.");
			bytes = write(data_socket, &buf[sent], size - sent);
			message_now("Sent.");
			if (bytes < 0) {
				perror("Writing to peer");
				exit(EXIT_FAILURE);
			}
		}
	if (size < 0) {
		perror("Reading from user");
		exit(EXIT_FAILURE);
	}
	message_now("Done writing.");
	if (update_socket) {
		pthread_mutex_lock(&flags_lock);
		state->tcpr.flags |= TCPR_DONE_WRITING;
		pthread_mutex_unlock(&flags_lock);
		if (write(update_socket, state, sizeof(*state)) < 0) {
			perror("Sending shutdown");
			exit(EXIT_FAILURE);
		}
	}
	if (shutdown(data_socket, SHUT_WR) < 0) {
		perror("Shutting down writing");
		exit(EXIT_FAILURE);
	}
	return NULL;
}

static void *read_updates(void *arg)
{
	struct update update;
	ssize_t size;

	(void)arg;

	while ((size = read(update_socket, &update, sizeof(update))) > 0) {
		message_now("Received update.");
		if (!state->tcpr.flags) {
			fprintf(stderr, "Establishing state from filter.\n");
			pthread_mutex_lock(&flags_lock);
			memcpy(state, &update, sizeof(update));
			pthread_cond_broadcast(&state_ready);
			pthread_mutex_unlock(&flags_lock);
		} else if (!update.tcpr.flags) {
			fprintf(stderr, "Recovering filter from state.\n");
			if (write(update_socket, state, sizeof(*state)) < 0) {
				perror("Sending filter recovery update");
				exit(EXIT_FAILURE);
			}
		} else if (update.tcpr.flags & TCPR_TIME_WAIT) {
			fprintf(stderr, "Entering TIME_WAIT.\n");
			pthread_mutex_lock(&flags_lock);
			state->tcpr.flags |= TCPR_TIME_WAIT;
			pthread_mutex_unlock(&flags_lock);
			/*  FIXME: should TIME_WAIT for safety */
			message_now("Removing filter state.");
			if (write(update_socket, state, sizeof(*state)) < 0) {
				perror("Closing filter state");
				exit(EXIT_FAILURE);
			}
			return NULL;
		} else {
			state->tcpr.delta = update.tcpr.delta;
			fprintf(stderr, "Recovered.\n");
			fprintf(stderr, "Peer has received %" PRIu32
					" bytes.\n",
					ntohl(update.tcpr.peer_ack)
						- ntohl(state->tcpr.peer_ack));
			fprintf(stderr, "Delta is now %" PRIu32 ".\n",
					state->tcpr.delta);
		}
	}
	if (size < 0) {
		perror("Reading update");
		exit(EXIT_FAILURE);
	}
	return NULL;
}

static void teardown_connections(void)
{
	message_now("Closing connection.");
	if (close(data_socket) < 0) {
		perror("Closing connection");
		exit(EXIT_FAILURE);
	}

	if (update_socket) {
		message_now("Closing update connection.");
		if (close(update_socket) < 0) {
			perror("Closing update connection");
			exit(EXIT_FAILURE);
		}
	}
}

static void teardown_state(const char *shm)
{
	message_now("Removing persistent state.");
	if (munmap(state, sizeof(*state)) < 0) {
		perror("Unmapping persistent state");
		exit(EXIT_FAILURE);
	}
	if (shm_unlink(shm) < 0) {
		perror("Destroying persistent state");
		exit(EXIT_FAILURE);
	}

	pthread_mutex_destroy(&flags_lock);
	pthread_cond_destroy(&state_ready);
}

int main(int argc, char **argv)
{
	const char *external_host = NULL;
	const char *external_port = NULL;
	const char *internal_host = NULL;
	const char *internal_port = NULL;
	const char *listen_port = NULL;
	const char *host = NULL;
	const char *port = NULL;
	const char *shm = NULL;
	int ret;
	pthread_t read_thread;
	pthread_t send_thread;
	pthread_t update_thread;

	while ((ret = getopt(argc, argv, "?s:i:e:l:c:")) != -1)
		switch (ret) {
		case 's':
			shm = optarg;
			break;
		case 'i':
			split_address(optarg, &internal_host, &internal_port);
			break;
		case 'e':
			split_address(optarg, &external_host, &external_port);
			break;
		case 'l':
			listen_port = optarg;
			break;
		case 'c':
			split_address(optarg, &host, &port);
			break;
		default:
			fprintf(stderr, "Usage: %s [-?] [-s SHM] "
				"[-i [HOST:]PORT] [-e [HOST:]PORT] "
				"[-l PORT] [-c [HOST:]PORT]\n", argv[0]);
			exit(EXIT_FAILURE);
		}

	if (!port && !listen_port)
		listen_port = "8888";

	if (!shm)
		shm = external_port ? "/tcpr-application" : "/tcpr-peer";
	setup_state(shm);

	if (external_port) {
		setup_update_connection(internal_host, internal_port,
					external_host, external_port);
		pthread_create(&update_thread, NULL, read_updates, NULL);
	}
	if (state->tcpr.flags)
		recover_connection(internal_host, listen_port);
	else
		setup_connection(internal_host, listen_port, host, port);

	pthread_create(&read_thread, NULL, read_from_peer, NULL);
	pthread_create(&send_thread, NULL, send_to_peer, NULL);

	if (update_socket)
		pthread_join(update_thread, NULL);
	pthread_join(read_thread, NULL);
	pthread_join(send_thread, NULL);

	teardown_connections();
	teardown_state(shm);
	return EXIT_SUCCESS;
}
