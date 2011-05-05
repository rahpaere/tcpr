#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;
	char *password;

	setup_test("tcpr-test", "test-app-data");
	password = get_password(htonl(net | 2), 8888, htonl(net | 3), 9999);

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 0xdeadbeef,
				0xcafebabe, test_options_size, test_options,
				peer_mss, peer_ws, password);

	fprintf(stderr, "Application: \"foo\"\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888, TH_ACK,
			0xcafebabe + 1, 0xdeadbeef + 1, 0, NULL, 4, "foo", password);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888, TH_ACK,
			0xcafebabe + 1, 0xdeadbeef + 1, 0, NULL, 4, "foo", password);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999, TH_ACK,
			0xdeadbeef + 1, 0xcafebabe + 5, 0, NULL, 0, NULL, password);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999, TH_ACK,
			0xdeadbeef + 1, 0xcafebabe + 5, 0, NULL, 0, NULL, password);

	cleanup_connection(net | 2, net | 4, 8888, 9999, 0xcafebabe + 5,
				0xdeadbeef + 1, 0);

	cleanup_test();
	return EXIT_SUCCESS;
}
