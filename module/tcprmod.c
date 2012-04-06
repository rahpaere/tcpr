#include <tcpr/filter.h>

#ifdef __KERNEL__
#include <net/tcp.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

static uint32_t shorten(uint32_t n)
{
	return (n >> 16) + (n & 0xffff);
}

enum tcpr_verdict tcpr_filter(struct tcpr *t, struct tcphdr *h, size_t size)
{
	uint32_t sum = h->check ^ 0xffff;
	uint8_t *end = (uint8_t *)((uint32_t *)h + h->doff);
	uint8_t *opt = (uint8_t *)(h + 1);
	uint8_t *tmp;

	while (opt < end && *opt != TCPOPT_EOL)
		switch (*opt) {
		case TCPOPT_NOP:
			opt++;
			break;
		case TCPOPT_MSS:
		case TCPOPT_SACK:
		case TCPOPT_SACK_PERM:
		case TCPOPT_TIMESTAMP:
		case TCPOPT_WINDOW:
			opt += opt[1];
			break;
		default:
			h->check = 0;
			for (tmp = opt + opt[1]; opt != tmp; opt++)
				*opt = TCPOPT_NOP;
			break;
		}

	if (h->rst)
		return TCPR_DROP;

	if (t->saved.external_port) {
		sum += (uint16_t)~h->source;
		h->source = t->saved.external_port;
		sum += h->source;
	}

	t->win = h->window;
	t->seq = htonl(ntohl(h->seq) + (h->syn ? 1 : 0) + size - h->doff * 4);

	if (h->fin) {
		t->fin = htonl(ntohl(t->seq) + 1 - t->delta);
		t->have_fin = 1;
	}

	if (h->syn) {
		if (h->ack) {
			t->saved.safe = htonl(ntohl(h->seq) + 1);
		} else if (!t->peer.have_ack) {
			t->saved.internal_port = h->source;
			if (!t->saved.external_port)
				t->saved.external_port = h->source;
			t->saved.peer.port = h->dest;
			if (h->check)
				h->check = ~shorten(shorten(sum));
			return TCPR_DELIVER;
		} else {
			t->delta = ntohl(t->seq) - ntohl(t->peer.ack);
			t->saved.done_writing = 0;
			t->have_fin = 0;
			return TCPR_RECOVER;
		}
	}

	if (t->have_fin && !t->saved.done_writing)
		return TCPR_RESET;

	t->ack = h->ack_seq;
	if (t->saved.done_reading) {
		t->saved.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
			t->done = 1;
	} else if (h->ack_seq != t->saved.ack) {
		if (size == (size_t)h->doff * 4)
			return TCPR_DROP;
		sum += shorten(~h->ack_seq);
		h->ack_seq = t->saved.ack;
		sum += shorten(h->ack_seq);
	}

	sum += shorten(~h->seq);
	h->seq = htonl(ntohl(h->seq) - t->delta);
	sum += shorten(h->seq);

	if (h->check)
		h->check = ~shorten(shorten(sum));
	return TCPR_DELIVER;
}

void tcpr_filter_peer(struct tcpr *t, struct tcphdr *h, size_t size)
{
	uint32_t sum = h->check ^ 0xffff;
	uint8_t *end = (uint8_t *)((uint32_t *)h + h->doff);
	uint8_t *opt = (uint8_t *)(h + 1);
	uint8_t *tmp;
	uint32_t sack;

	while (opt < end && *opt != TCPOPT_EOL)
		switch (*opt) {
		case TCPOPT_NOP:
			opt++;
			break;
		case TCPOPT_MSS:
			t->saved.peer.mss = (uint16_t)opt[2] << 8 | opt[3];
			opt += opt[1];
			break;
		case TCPOPT_WINDOW:
			t->saved.peer.ws = opt[2] + 1;
			opt += opt[1];
			break;
		case TCPOPT_SACK_PERM:
			t->saved.peer.sack_permitted = 1;
			opt += opt[1];
			break;
		case TCPOPT_SACK:
			tmp = opt + opt[1];
			for (opt += 2; opt < tmp; opt += 4) {
				sack = (uint32_t)opt[0] << 24
					| (uint32_t)opt[1] << 16
					| (uint32_t)opt[2] << 8
					| (uint32_t)opt[3];
				sack += t->delta;
				opt[0] = sack >> 24;
				opt[1] = sack >> 16;
				opt[2] = sack >> 8;
				opt[3] = sack;
			}
			break;
		case TCPOPT_TIMESTAMP:
			opt += opt[1];
			break;
		default:
			h->check = 0;
			for (tmp = opt + opt[1]; opt != tmp; opt++)
				*opt = TCPOPT_NOP;
			break;
		}

	if (t->saved.internal_port) {
		sum += (uint16_t)~h->dest;
		h->dest = t->saved.internal_port;
		sum += h->dest;
	}

	t->peer.win = h->window;

	if (h->syn) {
		printk(KERN_ERR "saving ports\n");
		t->saved.internal_port = h->dest;
		t->saved.external_port = h->dest;
		t->saved.peer.port = h->source;
		t->saved.ack = htonl(ntohl(h->seq) + 1);
		if (h->ack)
			t->saved.safe = h->ack_seq;
	} else {
		printk(KERN_ERR "not saving ports because not SYN\n");
	}

	if (h->fin) {
		t->peer.fin = htonl(ntohl(h->seq) + (h->syn ? 1 : 0) + 1 + size - h->doff * 4);
		t->peer.have_fin = 1;
	}

	if (h->ack) {
		if (!h->rst) {
			t->peer.ack = h->ack_seq;
			t->peer.have_ack = 1;
			if (t->have_fin && t->peer.have_fin && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
				t->done = 1;
		}

		sum += shorten(~h->ack_seq);
		h->ack_seq = htonl(ntohl(h->ack_seq) + t->delta);
		sum += shorten(h->ack_seq);
	}

	if (h->check)
		h->check = ~shorten(shorten(sum));
}

void tcpr_recover(struct tcphdr *h, struct tcpr *t)
{
	uint8_t *opt = (uint8_t *)(h + 1);
	size_t i = 0;

	memset(h, 0, sizeof(*h));
	h->source = t->saved.peer.port;
	h->dest = t->saved.internal_port;
	h->seq = htonl(ntohl(t->saved.ack) - 1);
	h->ack_seq = t->seq;
	h->doff = sizeof(*h) / 4;
	h->syn = 1;
	h->ack = 1;
	h->window = t->peer.win;

	if (t->saved.peer.mss) {
		opt[i++] = TCPOPT_MSS;
		opt[i++] = 4;
		opt[i++] = t->saved.peer.mss >> 8;
		opt[i++] = t->saved.peer.mss & 0xff;
	}

	if (t->saved.peer.ws) {
		opt[i++] = TCPOPT_WINDOW;
		opt[i++] = 3;
		opt[i++] = t->saved.peer.ws - 1;
	}

	if (t->saved.peer.sack_permitted) {
		opt[i++] = TCPOPT_SACK_PERM;
		opt[i++] = 2;
	}

	if (i % 4)
		opt[i++] = TCPOPT_EOL;
	h->doff += (i + 3) / 4;
}

void tcpr_update(struct tcphdr *h, struct tcpr *t)
{
	if (t->saved.done_reading) {
		t->saved.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
			t->done = 1;
	}

	memset(h, 0, sizeof(*h));
	h->source = t->saved.external_port;
	h->dest = t->saved.peer.port;
	h->seq = htonl(ntohl(t->seq) - t->delta);
	h->ack_seq = t->saved.ack;
	h->doff = sizeof(*h) / 4;
	h->ack = 1;
	h->window = t->win;
}

void tcpr_reset(struct tcphdr *h, struct tcpr *t)
{
	memset(h, 0, sizeof(*h));
	h->source = t->saved.peer.port;
	h->dest = t->saved.internal_port;
	h->seq = t->ack;
	h->doff = sizeof(*h) / 4;
	h->rst = 0;
	h->window = t->peer.win;
}
