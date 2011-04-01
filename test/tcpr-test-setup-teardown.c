#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	const uint32_t net = 0x0a0a0a00;

	setup_test("tcpr-test", "test-setup-teardown");

	setup_connection(net | 2, net | 4, net | 3, 8888, 9999, 7777, 
						7777, 0xdeadbeef, 0xcafebabe, 0, NULL, 0, 0);
	teardown_connection(net | 4, net | 3, 7777, 7777,
			net | 2, net | 4, 8888, 9999,
			0xcafebabe + 1, 0xdeadbeef + 1,
			0,
			TCPR_HAVE_ACK | TCPR_DONE_READING | TCPR_DONE_WRITING
				| TCPR_TIME_WAIT);

	cleanup_test();
	return EXIT_SUCCESS;
}
