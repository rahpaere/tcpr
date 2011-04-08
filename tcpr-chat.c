#include "tcpr.h"

#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

struct update {
	uint32_t peer_address;
	uint32_t address;
	struct tcpr_update tcpr;
};

static const char *bind_host;
static const char *bind_port;
static const char *connect_host;
static const char *connect_port;
static const char *filter_path = "tcpr-filter.socket";
static const char *application_path = "tcpr-application.socket";
static const char *state_file = "tcpr-application.state";
static struct sockaddr_un filter_address;
static int recovering;
static int filtering = 1;

static int data_socket;
static int update_socket;
static int state_fd;
static pthread_cond_t state_ready;
static pthread_mutex_t flags_lock;
static pthread_t read_thread;
static pthread_t send_thread;
static pthread_t update_thread;
static struct timespec timestamp;
static struct update *state;

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

static void *read_from_peer(void *arg)
{
	char buf[1024];
	ssize_t bytes;
	ssize_t sent;
	ssize_t size;

	(void)arg;

	if (filtering) {
		pthread_mutex_lock(&flags_lock);
		while (!state->tcpr.flags)
			pthread_cond_wait(&state_ready, &flags_lock);
		pthread_mutex_unlock(&flags_lock);
	}

	message_now("Starting receive loop.");
	while ((size = read(data_socket, buf, sizeof(buf))) > 0) {
		message_now("Received data.");
		for (sent = 0; sent < size; sent += bytes) {
			bytes = write(1, &buf[sent], size - sent);
			if (bytes < 0) {
				perror("Printing");
				exit(EXIT_FAILURE);
			}
			if (filtering) {
				state->tcpr.ack = htonl(ntohl(state->tcpr.ack)
								+ bytes);
				if (sendto(update_socket, state,
						sizeof(*state), 0,
						(struct sockaddr *)
						&filter_address,
						sizeof(filter_address)) < 0) {
					perror("Sending acknowledgment");
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	if (size < 0) {
		perror("Receiving");
		exit(EXIT_FAILURE);
	}

	message_now("Done receiving.");
	if (filtering) {
		pthread_mutex_lock(&flags_lock);
		state->tcpr.flags |= TCPR_DONE_READING;
		pthread_mutex_unlock(&flags_lock);
		if (sendto(update_socket, state, sizeof(*state), 0,
				(struct sockaddr *)&filter_address,
				sizeof(filter_address)) < 0) {
			perror("Sending input shutdown");
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

	if (filtering) {
		pthread_mutex_lock(&flags_lock);
		while (!state->tcpr.flags)
			pthread_cond_wait(&state_ready, &flags_lock);
		pthread_mutex_unlock(&flags_lock);
	}

	message_now("Starting send loop.");
	while ((size = read(0, buf, sizeof(buf))) > 0)
		for (sent = 0; sent < size; sent += bytes) {
			clock_gettime(CLOCK_REALTIME, &timestamp);
			bytes = write(data_socket, &buf[sent], size - sent);
			message("Sending data.");
			message_now("Sent.");
			if (bytes < 0) {
				perror("Sending");
				exit(EXIT_FAILURE);
			}
		}
	if (size < 0) {
		perror("Reading");
		exit(EXIT_FAILURE);
	}

	message_now("Done sending.");
	if (filtering) {
		pthread_mutex_lock(&flags_lock);
		state->tcpr.flags |= TCPR_DONE_WRITING;
		pthread_mutex_unlock(&flags_lock);
		if (sendto(update_socket, state, sizeof(*state), 0,
				(struct sockaddr *)&filter_address,
				sizeof(filter_address)) < 0) {
			perror("Sending input shutdown");
			exit(EXIT_FAILURE);
		}
	}
	if (shutdown(data_socket, SHUT_WR) < 0) {
		perror("Shutting down output");
		exit(EXIT_FAILURE);
	}
	return NULL;
}

static void *read_updates(void *arg)
{
	struct update update;
	ssize_t size;

	(void)arg;

	size = read(update_socket, &update, sizeof(update));
	clock_gettime(CLOCK_REALTIME, &timestamp);
	if (size < 0) {
		perror("Receiving update");
		exit(EXIT_FAILURE);
	}
	if (recovering) {
		message("Recovered.");
		state->tcpr.delta = update.tcpr.delta;
		fprintf(stderr, "Peer has acknowledged %" PRIu32 " bytes.\n",
				ntohl(update.tcpr.peer_ack)
					- ntohl(state->tcpr.peer_ack));
		fprintf(stderr, "Delta is now %" PRIu32 ".\n",
				state->tcpr.delta);
	} else {
		message("Connected.");
		pthread_mutex_lock(&flags_lock);
		memcpy(state, &update, sizeof(update));
		pthread_cond_broadcast(&state_ready);
		pthread_mutex_unlock(&flags_lock);
	}

	while ((size = read(update_socket, &update, sizeof(update))) > 0) {
		clock_gettime(CLOCK_REALTIME, &timestamp);
		if (!update.tcpr.flags) {
			message("Filter needs recovery.");
			if (sendto(update_socket, state, sizeof(*state), 0,
					(struct sockaddr *)&filter_address,
					sizeof(filter_address)) < 0) {
				perror("Sending state");
				exit(EXIT_FAILURE);
			}
			message_now("Sent state to filter.");
		} else if (update.tcpr.flags & TCPR_TIME_WAIT) {
			message("Entering TIME_WAIT.");
			/*  FIXME: wait for lagging packets */
			pthread_mutex_lock(&flags_lock);
			state->tcpr.flags |= TCPR_FINISHED;
			pthread_mutex_unlock(&flags_lock);
			if (sendto(update_socket, state, sizeof(*state), 0,
					(struct sockaddr *)&filter_address,
					sizeof(filter_address)) < 0) {
				perror("Removing filter state");
				exit(EXIT_FAILURE);
			}
			message_now("Removed filter state.");
			return NULL;
		} else {
			message("Unexpected update.");
		}
	}
	if (size < 0) {
		perror("Receiving update");
		exit(EXIT_FAILURE);
	}
	return NULL;
}

static void setup_state(void)
{
	message_now("Initializing persistent state.");

	state_fd = open(state_file, O_RDWR | O_CREAT, 0600);
	if (state_fd < 0) {
		perror("Opening persistent state");
		exit(EXIT_FAILURE);
	}
	if (ftruncate(state_fd, sizeof(*state)) < 0) {
		perror("Resizing persistent state");
		exit(EXIT_FAILURE);
	}
	state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
			MAP_SHARED, state_fd, 0);
	if (state == MAP_FAILED) {
		perror("Mapping persistent state");
		exit(EXIT_FAILURE);
	}

	if (state->tcpr.flags && !(state->tcpr.flags & TCPR_TIME_WAIT))
		recovering = 1;

	pthread_mutex_init(&flags_lock, NULL);
	pthread_cond_init(&state_ready, NULL);
}

static void setup_update_connection(void)
{
	struct sockaddr_un addr;

	message_now("Establishing update connection.");

	update_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (update_socket < 0) {
		perror("Creating update socket");
		exit(EXIT_FAILURE);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, application_path, sizeof(addr.sun_path) - 1);
	unlink(application_path);
	if (bind(update_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Binding update socket");
		exit(EXIT_FAILURE);
	}

	memset(&filter_address, 0, sizeof(filter_address));
	filter_address.sun_family = AF_UNIX;
	strncpy(filter_address.sun_path, filter_path,
		sizeof(filter_address.sun_path) - 1);

	pthread_create(&update_thread, NULL, read_updates, NULL);
}

static void setup_socket(int s)
{
	int yes = 1;
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
}

static void setup_connection(void)
{
	int ret;
	int s;
	struct addrinfo *ai;
	struct addrinfo hints;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	setup_socket(s);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (bind_host || bind_port) {
		hints.ai_flags = (connect_port ? 0 : AI_PASSIVE);
		ret = getaddrinfo(bind_host, bind_port, &hints, &ai);
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

	if (connect_port) {
		message_now("Connecting to peer.");
		hints.ai_flags = 0;
		ret = getaddrinfo(connect_host, connect_port, &hints, &ai);
		if (ret) {
			fprintf(stderr, "Resolving peer address: %s\n",
					gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("Connecting");
			exit(EXIT_FAILURE);
		}
		clock_gettime(CLOCK_REALTIME, &timestamp);
		freeaddrinfo(ai);
		data_socket = s;
	} else {
		message_now("Waiting for peer to connect.");
		if (listen(s, 1) < 0) {
			perror("Listening");
			exit(EXIT_FAILURE);
		}
		data_socket = accept(s, NULL, NULL);
		clock_gettime(CLOCK_REALTIME, &timestamp);
		if (data_socket < 0) {
			perror("Accepting");
			exit(EXIT_FAILURE);
		}
		close(s);
	}

	message("Connected.");
	pthread_create(&read_thread, NULL, read_from_peer, NULL);
	pthread_create(&send_thread, NULL, send_to_peer, NULL);
}

static void recover_connection(void)
{
	struct sockaddr_in addr;

	message_now("Recovering connection.");

	data_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (data_socket < 0) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	setup_socket(data_socket);

	addr.sin_family = AF_INET;
	addr.sin_port = state->tcpr.port;
	addr.sin_addr.s_addr = state->address;
	if (bind(data_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Binding");
		exit(EXIT_FAILURE);
	}

	addr.sin_family = AF_INET;
	addr.sin_port = state->tcpr.peer_port;
	addr.sin_addr.s_addr = state->peer_address;
	if (connect(data_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Connecting");
		exit(EXIT_FAILURE);
	}

	message_now("Connected.");
	pthread_create(&read_thread, NULL, read_from_peer, NULL);
	pthread_create(&send_thread, NULL, send_to_peer, NULL);
}

static void finish(void)
{
	pthread_join(read_thread, NULL);
	pthread_join(send_thread, NULL);

	message_now("Closing connection.");
	if (close(data_socket) < 0) {
		perror("Closing connection");
		exit(EXIT_FAILURE);
	}

	if (update_socket) {
		message_now("Closing update connection.");
		pthread_join(update_thread, NULL);
		if (close(update_socket) < 0) {
			perror("Closing update connection");
			exit(EXIT_FAILURE);
		}
		unlink(application_path);

		message_now("Removing persistent state.");
		if (munmap(state, sizeof(*state)) < 0) {
			perror("Unmapping persistent state");
			exit(EXIT_FAILURE);
		}
		if (close(state_fd) < 0) {
			perror("Closing persistent state");
			exit(EXIT_FAILURE);
		}
		if (unlink(state_file) < 0) {
			perror("Destroying persistent state");
			exit(EXIT_FAILURE);
		}

		pthread_mutex_destroy(&flags_lock);
		pthread_cond_destroy(&state_ready);
	}
}

static void split_address(char *address, const char **host, const char **port)
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

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "b:c:a:f:s:p?")) != -1)
		switch (opt) {
		case 'b':
			split_address(optarg, &bind_host, &bind_port);
			break;
		case 'c':
			split_address(optarg, &connect_host, &connect_port);
			break;
		case 'a':
			application_path = optarg;
			break;
		case 'f':
			filter_path = optarg;
			break;
		case 's':
			state_file = optarg;
			break;
		case 'p':
			filtering = 0;
			break;
		default:
			fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
			fprintf(stderr, "  -b HOST:[PORT]  "
				"Bind to HOST at PORT.\n");
			fprintf(stderr, "  -c HOST:[PORT]  "
				"Connect to HOST at PORT.\n");
			fprintf(stderr, "  -a PATH         "
				"Receive updates at the UNIX socket PATH.\n");
			fprintf(stderr, "  -f PATH         "
				"Send updates to the UNIX socket PATH.\n");
			fprintf(stderr, "  -s FILE         "
				"Keep persistent state in FILE.\n");
			fprintf(stderr, "  -p              "
				"Act as the peer; i.e. ignore TCPR.\n");
			fprintf(stderr, "  -?              "
				"Print this help message and exit.\n");
			exit(EXIT_FAILURE);
		}

	if (!connect_port && connect_host)
		connect_port = "8888";
	if (!bind_port && (bind_host || !connect_port))
		bind_port = "8888";

	if (filtering) {
		setup_state();
		setup_update_connection();
	}

	if (recovering)
		recover_connection();
	else
		setup_connection();

	finish();
	return EXIT_SUCCESS;
}
