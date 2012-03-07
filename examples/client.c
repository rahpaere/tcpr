#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int c;
	struct sockaddr_in addr;
	char msg[1];
	ssize_t msglen;

	(void)argc;
	(void)argv;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(6666);
	inet_aton("127.0.0.2", &addr.sin_addr);

	printf("Connecting.\n");
	c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (c < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	printf("Sending a greeting.\n");
	msg[0] = '\n';
	msglen = send(c, msg, sizeof(msg), 0);
	if (msglen < 0) {
		perror("send");
		exit(EXIT_FAILURE);
	}

	printf("Waiting for the echo.\n");
	msglen = recv(c, msg, sizeof(msg), 0);
	if (msglen < 0) {
		perror("recv");
		exit(EXIT_FAILURE);
	}

	printf("Closing gracefully.\n");
	if (close(c) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}

	return 0;
}
