#ifndef TCPR_UTIL_H
#define TCPR_UTIL_H

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

int resolve_address(struct sockaddr_in *addr, const char *host,
		    const char *port);
int connect_to_tcpr(void);
int get_tcpr_state(struct tcpr_ip4 *state, int sock, struct sockaddr_in *addr,
		   struct sockaddr_in *srcaddr);

#endif
