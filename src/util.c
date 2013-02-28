#include <tcpr/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int resolve_address(struct sockaddr_in *addr, const char *host, const char *port)
{
        int err;
        struct addrinfo *ai;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        err = getaddrinfo(host, port, &hints, &ai);
        if (err)
                return err;

        memcpy(addr, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
        return 0;
}

int connect_to_tcpr(struct sockaddr_in *addr)
{
	int s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		close(s);
		return -1;
	}

	return s;
}

int get_tcpr_state(struct tcpr_ip4 *state, int sock, struct sockaddr_in *addr, struct sockaddr_in *srcaddr)
{
	memset(state, 0, sizeof(*state));
	state->peer_address = addr->sin_addr.s_addr;
	state->tcpr.hard.peer.port = addr->sin_port;
	state->tcpr.hard.port = srcaddr->sin_port;

	if (send(sock, state, sizeof(*state), 0) < 0)
		return -1;
	if (recv(sock, state, sizeof(*state), 0) < 0)
		return -1;

	return 0;
}
