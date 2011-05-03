#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;

	setup_test("tcpr-test", "test-spurious-fins");

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 0xdeadbeef,
				0xcafebabe, test_options_size, test_options,
				peer_mss, peer_ws);

	fprintf(stderr, "Application: FIN (failure)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK | TH_FIN, 0xcafebabe + 1, 0xdeadbeef + 1, 0,
			NULL, 0, NULL);

	fprintf(stderr, "     Filter: RST\n");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999, TH_RST,
			0xdeadbeef + 1, 0, 0, NULL, 0, NULL);

	cleanup_connection(net | 2, net | 4, 8888, 9999, 0xcafebabe + 1,
				0xdeadbeef + 1, 0);

	cleanup_test();
	return EXIT_SUCCESS;
}
