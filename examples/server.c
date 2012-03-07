#include <tcpr/application.h>

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int s;
	int c;
	struct tcpr_connection tcpr;
	struct sockaddr_in addr;
	struct sockaddr_in peer;
	socklen_t addrlen = sizeof(addr);
	socklen_t peerlen = sizeof(peer);
	char msg[1];
	ssize_t msglen;

	(void)argc;
	(void)argv;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(6666);
	addr.sin_addr.s_addr = INADDR_ANY;

	printf("Waiting for a connection.\n");
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if (bind(s, (struct sockaddr *)&addr, addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (listen(s, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	c = accept(s, (struct sockaddr *)&peer, &peerlen);
	if (c < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	if (getsockname(c, (struct sockaddr *)&addr, &addrlen) < 0) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}

	printf("Synchronizing TCPR state.\n");
	if (tcpr_setup_connection(&tcpr, peer.sin_addr.s_addr, peer.sin_port,
					addr.sin_port, 0) < 0) {
		perror("tcpr_setup_connection");
		exit(EXIT_FAILURE);
	};

	printf("Waiting for greeting.\n");
	msglen = recv(c, msg, sizeof(msg), 0);
	if (msglen < 0) {
		perror("recv");
		exit(EXIT_FAILURE);
	}

	printf("Failing.\n");
	if (close(c) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}

	printf("Recovering.\n");
	c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (c < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	addr.sin_port = htons(0);
	if (bind(c, (struct sockaddr *)&addr, addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (getsockname(c, (struct sockaddr *)&addr, &addrlen) < 0) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}
	tcpr.state->saved.internal_port = addr.sin_port;
	if (connect(c, (struct sockaddr *)&peer, peerlen) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	printf("Recovering the greeting.\n");
	msglen = recv(c, msg, sizeof(msg), 0);
	if (msglen < 0) {
		perror("recv");
		exit(EXIT_FAILURE);
	}
	tcpr_checkpoint_input(&tcpr, msglen);

	printf("Sending an echo.\n");
	msglen = send(c, msg, sizeof(msg), 0);
	if (msglen < 0) {
		perror("send");
		exit(EXIT_FAILURE);
	}

	printf("Closing gracefully.\n");
	tcpr_close(&tcpr);
	if (close(c) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}
	tcpr_wait(&tcpr);
	tcpr_teardown_connection(&tcpr);

	return 0;
}
