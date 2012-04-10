#ifndef TCPR_FILTER_H
#define TCPR_FILTER_H

#include <tcpr/types.h>

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/tcp.h>
#else
#include <netinet/tcp.h>
#include <stdlib.h>
#endif

enum tcpr_verdict {
	TCPR_DROP,
	TCPR_DELIVER,
	TCPR_ACKNOWLEDGE,
	TCPR_RECOVER,
	TCPR_RESET,
};

enum tcpr_verdict tcpr_filter(struct tcpr *t, struct tcphdr *h, size_t size);
enum tcpr_verdict tcpr_filter_peer(struct tcpr *t, struct tcphdr *h, size_t size);
enum tcpr_verdict tcpr_update(struct tcpr *t, struct tcpr *u);

void tcpr_acknowledge(struct tcphdr *h, struct tcpr *t);
void tcpr_recover(struct tcphdr *h, struct tcpr *t);
void tcpr_reset(struct tcphdr *h, struct tcpr *t);

#endif
