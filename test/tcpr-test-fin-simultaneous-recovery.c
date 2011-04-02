#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;

	setup_test("tcpr-test", "test-fin-simultaneous-recovery");

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 7777, 
						7777, 0xdeadbeef, 0xcafebabe, 0, NULL, 0, 0);


	fprintf(stderr, "Application: \"quux\"\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 5, "quux");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 5, "quux");

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 6,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: FIN\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 6,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 6, 0xdeadbeef + 2,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 6, 0xdeadbeef + 1,
			0,
			TCPR_HAVE_ACK | TCPR_DONE_READING);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 6, 0xdeadbeef + 2,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 6, 0xdeadbeef + 1,
			0,
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING);

	fprintf(stderr, "Application: FIN\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 6, 0xdeadbeef + 2,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 6, 0xdeadbeef + 2,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 2, 0xcafebabe + 7,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 2, 0xcafebabe + 7,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (TIME_WAIT)\n");
	recv_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 7, 0xdeadbeef + 2, 0, 0,
			0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	teardown_connection(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 7, 0xdeadbeef + 2,
			0,
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	fprintf(stderr, "Application: \"a\"\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999, 0, 0, 0, 0, 0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead + 2, 0xbabedeed - 4,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: \"a\" (retransmit)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed - 4,
			0, NULL, 2, "a");

	teardown_connection(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	fprintf(stderr, "Application: SYN (simultaneous recovery)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_SYN, 0xcafebabe, 0, 0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_SYN, 0xcafebabe, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK (answer unacceptable SYN)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0, 0, 0, 0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 5, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (retransmit)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_SYN, 0xcafebabe, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef + 4, 0xcafebabe + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 4, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 5, 0, 0,
			0, TCPR_HAVE_ACK);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update (reset)\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 5,
			0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	teardown_connection(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 1,
			0,
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	cleanup_test();
	return EXIT_SUCCESS;
}

