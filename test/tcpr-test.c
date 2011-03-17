#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;

	tun = open_tun("tcpr-test");
	external_log = open_log("test-external.pcap");
	internal_log = open_log("test-internal.pcap");

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 7777, 
						7777, 0xdeadbeef, 0xcafebabe, 0, NULL, 0, 0);

	fprintf(stderr, "Application: \"foo\"\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 4, "foo");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 1, 0xdeadbeef + 1,
			0, NULL, 4, "foo");

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"bar\"\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 4, "bar");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 1, 0xcafebabe + 5,
			0, NULL, 4, "bar");

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: FIN (failure)\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_ACK | TH_FIN, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: RST\n");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_RST, 0xdeadbeef + 5, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\"\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 4, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: RST\n");
	send_segment(internal_log, net | 4, net | 2, 9999, 8888,
			TH_RST, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (recovery)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef + 4, 0xfeedbead + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, 0,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: \"baz\" (retransmit)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 4, "baz");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xfeedbead + 1,
			0, NULL, 4, "baz");

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 9,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 9,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: \"quux\"\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 9,
			0, NULL, 5, "quux");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 9,
			0, NULL, 5, "quux");

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 9, 0xcafebabe + 10,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 9, 0xfeedbead + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: FIN\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 9, 0xcafebabe + 10,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_FIN | TH_ACK, 0xdeadbeef + 9, 0xfeedbead + 6,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 6, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 10, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 10, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 10, 0xdeadbeef + 9,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING);

	fprintf(stderr, "Application: FIN\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xfeedbead + 6, 0xdeadbeef + 10,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_FIN | TH_ACK, 0xcafebabe + 10, 0xdeadbeef + 10,
			0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 10, 0xcafebabe + 11,
			0, NULL, 0, NULL);
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_ACK, 0xdeadbeef + 10, 0xfeedbead + 7,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (TIME_WAIT)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 11, 0xdeadbeef + 10, 0, 0,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	teardown_connection(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 11, 0xdeadbeef + 10,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	fprintf(stderr, "Application: \"a\"\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999, 0, 0, 0, 0, 0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead + 2, 0xbabedeed - 4,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: \"a\" (retransmit)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed,
			0, NULL, 2, "a");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xbeefbead, 0xbabedeed - 4,
			0, NULL, 2, "a");

	teardown_connection(net | 5, net | 3, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xbeefbead, 0xbabedeed - 4, 0,
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	fprintf(stderr, "Application: SYN (simultaneous recovery)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "       Peer: ACK (answer unacceptable SYN)\n");
	send_segment(external_log, net | 2, net | 3, 8888, 9999,
			TH_ACK, 0xdeadbeef + 5, 0xcafebabe + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update (failure)\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0, 0, 0, 0, 0);

	fprintf(stderr, "Application: update\n");
	send_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, TCPR_HAVE_ACK);

	fprintf(stderr, "     Filter: ACK\n");
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: SYN (retransmit)\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_SYN, 0xfeedbead, 0, 0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: SYN ACK\n");
	recv_segment(internal_log, net | 2, net | 5, 8888, 9999,
			TH_SYN | TH_ACK, 0xdeadbeef + 4, 0xfeedbead + 1,
			0, NULL, 0, NULL);

	fprintf(stderr, "     Filter: update\n");
	recv_update(net | 3, net | 5, 7777, 7777,
			net | 2, net | 5, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5, 0, 0,
			(0xfeedbead + 1) - (0xcafebabe + 5), TCPR_HAVE_ACK);

	fprintf(stderr, "Application: ACK\n");
	send_segment(internal_log, net | 5, net | 2, 9999, 8888,
			TH_ACK, 0xfeedbead + 1, 0xdeadbeef + 5,
			0, NULL, 0, NULL);
	recv_segment(external_log, net | 3, net | 2, 9999, 8888,
			TH_ACK, 0xcafebabe + 5, 0xdeadbeef + 5,
			0, NULL, 0, NULL);

	fprintf(stderr, "Application: update (reset)\n");
	send_update(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 5, 0xdeadbeef + 5,
			(0xfeedbead + 1) - (0xcafebabe + 5),
			TCPR_HAVE_ACK | TCPR_TIME_WAIT);

	if (fclose(external_log)) {
		perror("Closing external log file");
		exit(EXIT_FAILURE);
	}
	if (fclose(internal_log)) {
		perror("Closing internal log file");
		exit(EXIT_FAILURE);
	}
	if (close(tun)) {
		perror("Closing TUN device");
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}
