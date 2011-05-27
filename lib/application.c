#include <tcpr/application.h>

#include <errno.h>
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

static const char state_path_format[] =
    "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".state";
static const char control_path_format[] =
    "/var/tmp/tcpr-%s-%" PRId16 "-%" PRId16 ".ctl";

static struct tcpr *open_state(const char *peer_host, uint16_t peer_port,
			       uint16_t port)
{
	char path[sizeof(state_path_format) + strlen(peer_host) + 10];
	int fd;
	int saved_errno;
	struct tcpr *t;

	sprintf(path, state_path_format, peer_host, ntohs(peer_port),
		ntohs(port));

	fd = open(path, O_RDWR, 0600);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, sizeof(*t)) < 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return NULL;
	}

	t = mmap(NULL, sizeof(*t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return t == MAP_FAILED ? NULL : t;
}

static void setup_control_address(struct sockaddr_un *control_address,
				  const char *peer_host, uint16_t peer_port,
				  uint16_t port)
{
	memset(control_address, 0, sizeof(*control_address));
	control_address->sun_family = AF_UNIX;
	sprintf(control_address->sun_path, control_path_format, peer_host,
		ntohs(peer_port), ntohs(port));
}

int tcpr_setup_connection(struct tcpr_connection *c, int sock)
{
	char peer_host[INET_ADDRSTRLEN];
	socklen_t addrlen;
	struct sockaddr_in address;
	struct sockaddr_in peer_address;

	addrlen = sizeof(address);
	if (getsockname(sock, (struct sockaddr *)&address, &addrlen) < 0)
		return -1;

	addrlen = sizeof(peer_address);
	if (getpeername(sock, (struct sockaddr *)&peer_address, &addrlen) < 0)
		return -1;

	inet_ntop(AF_INET, &peer_address.sin_addr, peer_host,
		  sizeof(peer_host));

	c->state =
	    open_state(peer_host, peer_address.sin_port, address.sin_port);
	if (!c->state)
		return -1;

	c->control_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (c->control_socket < 0) {
		munmap(c->state, sizeof(*c->state));
		return -1;
	}

	setup_control_address(&c->control_address, peer_host,
			      peer_address.sin_port, address.sin_port);
	return 0;
}

void tcpr_teardown_connection(struct tcpr_connection *c)
{
	munmap(c->state, sizeof(*c->state));
	close(c->control_socket);
}

static int update(struct tcpr_connection *c)
{
	static const char message[] = "1\n";
	return sendto(c->control_socket, message, sizeof(message), 0,
		      (struct sockaddr *)&c->control_address,
		      sizeof(c->control_address));
}

int tcpr_consume(struct tcpr_connection *c, size_t bytes)
{
	c->state->saved.ack = htonl(ntohl(c->state->saved.ack) + bytes);
	return update(c);
}

int tcpr_done_reading(struct tcpr_connection *c)
{
	c->state->saved.done_reading = 1;
	return update(c);
}

void tcpr_done_writing(struct tcpr_connection *c)
{
	c->state->saved.done_writing = 1;
}
