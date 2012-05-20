#include <stdio.h>
#include <getopt.h>
#include <xtables.h>

static void tcpr_tg_help(void)
{
	printf("TCPR target options\n"
	       "  --peer  Filter packets from peers.\n");
}

static const struct option tcpr_tg_opts[] = {
	{"peer", 0, NULL, 'P'},
	{.name = NULL},
};

static int tcpr_tg_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_target **target)
{
	int *peer = (int *)(*target)->data;

	(void)argv;
	(void)flags;
	(void)entry;

	if (c == 'P') {
		*peer = !invert;
		return 1;
	}
	return 0;
}

static void tcpr_tg_print(const void *ip, const struct xt_entry_target *target,
			  int numeric)
{
	const int *peer = (const int *)target->data;

	(void)ip;
	(void)numeric;

	if (*peer)
		printf(" TCPR --peer ");
	else
		printf(" TCPR ");
}

static void tcpr_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const int *peer = (const int *)target->data;

	(void)ip;

	if (*peer)
		printf(" --peer");
}

static struct xtables_target tcpr_tg_reg = {
	.name = "TCPR",
	.version = XTABLES_VERSION,
	.family = AF_INET,
	.size = XT_ALIGN(sizeof(int)),
	.userspacesize = XT_ALIGN(sizeof(int)),
	.help = tcpr_tg_help,
	.parse = tcpr_tg_parse,
	.print = tcpr_tg_print,
	.save = tcpr_tg_save,
	.extra_opts = tcpr_tg_opts,
};

static __attribute__((constructor)) void tcpr_tg_ldr(void)
{
	xtables_register_target(&tcpr_tg_reg);
}
