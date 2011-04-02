#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;

	setup_test("tcpr-test", "test-failure-recovery");

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 7777, 
						7777, 0xdeadbeef, 0xcafebabe, 0, NULL, 0, 0);

	fprintf(stderr, "Application: FIN (failure)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK | TH_FIN, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: RST\n");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_RST, 0xdeadbeef + 1, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\"\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: RST\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_RST, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (recovery)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef, 0xfeedbead + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 1, 0, 0,
			(0xfeedbead + 1) - (0xcafebabe + 1), TCPR_HAVE_ACK);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 1,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\" (retransmit)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 1,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xfeedbead + 1,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 1), TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	teardown_connection(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 1),
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	cleanup_test();
	return EXIT_SUCCESS;
}
