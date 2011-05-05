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

	setup_test("tcpr-test", "test-graceful-shutdown");
	password = get_password(htonl(net | 2), 8888, htonl(net | 3), 9999);

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 0xdeadbeef,
				0xcafebabe, 0, NULL, 0, 0, password);

	fprintf(stderr, "       Peer: FIN\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1, 0,
			NULL, 0, NULL, password);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1, 0,
			NULL, 0, NULL, password);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888, TH_ACK,
			0xcafebabe + 1, 0xdeadbeef + 2, 0, NULL, 0, NULL, password);

	fprintf(stderr, "Application: update\n");
	send_update(net | 2, net | 4, 8888, 9999, 0xcafebabe + 1,
			0xdeadbeef + 1, 0, 0, 0,
			TCPR_HAVE_ACK | TCPR_DONE_READING);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888, TH_ACK,
			0xcafebabe + 1, 0xdeadbeef + 2, 0, NULL, 0, NULL, password);

	fprintf(stderr, "Application: update\n");
	send_update(net | 2, net | 4, 8888, 9999, 0xcafebabe + 1,
			0xdeadbeef + 1, 0, 0, 0,
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING);

	fprintf(stderr, "Application: FIN\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 2, 0,
			NULL, 0, NULL, password);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 2, 0,
			NULL, 0, NULL, password);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999, TH_ACK,
			0xdeadbeef + 2, 0xcafebabe + 2, 0, NULL, 0, NULL, password);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999, TH_ACK,
			0xdeadbeef + 2, 0xcafebabe + 2, 0, NULL, 0, NULL, password);

	fprintf(stderr, "     Filter: update (TIME_WAIT)\n");

	recv_update(net | 2, net | 4, 8888, 9999, 0xcafebabe + 2,
			0xdeadbeef + 2, 0, 0, 0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	cleanup_connection(net | 2, net | 4, 8888, 9999, 0xcafebabe + 2,
				0xdeadbeef + 2, 0);

	cleanup_test();
	return EXIT_SUCCESS;
}

