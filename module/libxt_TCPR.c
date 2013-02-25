#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>

static void tcpr_tg_help(void)
{
	printf("TCPR target options:\n"
	       "  --addr IP  handle packets from application IP\n");
}

static const struct option tcpr_tg_opts[] = {
	{"address", true, NULL, 'a'},
	{NULL, 0, NULL, 0},
};

static void tcpr_tg_init(struct xt_entry_target *target)
{
	uint32_t *peer = (void *)target->data;
	*peer = 0;
}

static int tcpr_tg_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_target **target)
{
	uint32_t *addr = (void *)(*target)->data;
	uint32_t *tmp;

	(void)argv;
	(void)flags;
	(void)entry;

	switch (c) {
	case 'a':
		xtables_param_act(XTF_NO_INVERT, "TCPR", "addr", invert);
		tmp = (uint32_t *)xtables_numeric_to_ipaddr(optarg);
		if (!tmp)
			xtables_param_act(XTF_BAD_VALUE, "TCPR", "--addr", optarg);
		memcpy(addr, tmp, sizeof(*tmp));
		return true;
	}

	return false;
}

static void tcpr_tg_print(const void *entry, const struct xt_entry_target *target,
			  int numeric)
{
	const uint32_t *addr = (const void *)target->data;

	(void)entry;
	(void)numeric;

	if (*addr)
		printf(" TCPR --addr %s ", xtables_ipaddr_to_numeric((struct in_addr *)addr));
	else
		printf(" TCPR ");
}

static void tcpr_tg_save(const void *entry, const struct xt_entry_target *target)
{
	const uint32_t *addr = (const void *)target->data;

	(void)entry;

	if (*addr)
		printf(" --addr %s ", xtables_ipaddr_to_numeric((struct in_addr *)addr));
}

static struct xtables_target tcpr_tg_reg = {
	.version = XTABLES_VERSION,
	.name = "TCPR",
	.family = AF_INET,
	.size = XT_ALIGN(sizeof(uint32_t)),
	.userspacesize = XT_ALIGN(sizeof(uint32_t)),
	.help = tcpr_tg_help,
	.init = tcpr_tg_init,
	.parse = tcpr_tg_parse,
	.print = tcpr_tg_print,
	.save = tcpr_tg_save,
	.extra_opts = tcpr_tg_opts,
};

static __attribute__((constructor)) void tcpr_tg_ldr(void)
{
	xtables_register_target(&tcpr_tg_reg);
}
