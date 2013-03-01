#include <tcpr/types.h>
#include <tcpr/util.h>

#include <stdio.h>

int main(int argc, char **argv)
{
	struct tcpr_ip4 state;

	(void)argc;
	(void)argv;

	while (fread(&state, sizeof(state), 1, stdin)) {
		state.tcpr.failed = 1;
		fwrite(&state, sizeof(state), 1, stdout);
	}

	return EXIT_SUCCESS;
}
