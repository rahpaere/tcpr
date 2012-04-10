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
	uint32_t check = h->check ^ 0xffff;
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

	if (h->rst) {
		t->failed = 1;
		return TCPR_DROP;
	}

	if (t->hard.port) {
		check += (uint16_t)~h->source;
		h->source = t->hard.port;
		check += h->source;
	}

	t->win = h->window;
	t->seq = htonl(ntohl(h->seq) + (h->syn ? 1 : 0) + size - h->doff * 4);

	if (h->fin) {
		t->fin = htonl(ntohl(t->seq) + 1 - t->delta);
		t->have_fin = 1;
		if (!t->hard.done_writing)
			t->failed = 1;
	}

	if (!h->ack) {
		t->failed = 0;
		if (t->peer.have_ack) {
			t->delta = ntohl(t->seq) - ntohl(t->peer.ack);
			t->hard.done_writing = 0;
			t->have_fin = 0;
			return TCPR_RECOVER;
		} else {
			t->port = h->source;
			if (!t->hard.port)
				t->hard.port = h->source;
			t->hard.peer.port = h->dest;
			if (h->check)
				h->check = ~shorten(shorten(check));
			return TCPR_DELIVER;
		}
	}

	if (t->failed)
		return TCPR_RESET;

	t->ack = h->ack_seq;
	if (t->hard.done_reading) {
		t->hard.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->hard.ack)
			t->done = 1;
	} else if (h->ack_seq != t->hard.ack) {
		if (size == (size_t)h->doff * 4)
			return TCPR_DROP;
		check += shorten(~h->ack_seq);
		h->ack_seq = t->hard.ack;
		check += shorten(h->ack_seq);
	}

	check += shorten(~h->seq);
	h->seq = htonl(ntohl(h->seq) - t->delta);
	check += shorten(h->seq);

	if (h->check)
		h->check = ~shorten(shorten(check));
	return TCPR_DELIVER;
}

enum tcpr_verdict tcpr_filter_peer(struct tcpr *t, struct tcphdr *h, size_t size)
{
	uint32_t check = h->check ^ 0xffff;
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
			t->hard.peer.mss = (uint16_t)opt[2] << 8 | opt[3];
			opt += opt[1];
			break;
		case TCPOPT_WINDOW:
			t->hard.peer.ws = opt[2] + 1;
			opt += opt[1];
			break;
		case TCPOPT_SACK_PERM:
			t->hard.peer.sack_permitted = 1;
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

	if (t->port) {
		check += (uint16_t)~h->dest;
		h->dest = t->port;
		check += h->dest;
	}

	t->peer.win = h->window;

	if (h->syn) {
		t->port = h->dest;
		t->hard.port = h->dest;
		t->hard.peer.port = h->source;
		t->hard.ack = htonl(ntohl(h->seq) + 1);
	}

	if (h->fin) {
		t->peer.fin = htonl(ntohl(h->seq) + (h->syn ? 1 : 0) + 1 + size - h->doff * 4);
		t->peer.have_fin = 1;
	}

	if (h->ack) {
		if (!h->rst) {
			t->peer.ack = h->ack_seq;
			t->peer.have_ack = 1;
			if (t->have_fin && t->peer.have_fin && t->peer.ack == t->fin && t->peer.fin == t->hard.ack)
				t->done = 1;
		}

		check += shorten(~h->ack_seq);
		h->ack_seq = htonl(ntohl(h->ack_seq) + t->delta);
		check += shorten(h->ack_seq);
	}

	if (h->check)
		h->check = ~shorten(shorten(check));

	return t->failed ? TCPR_DROP : TCPR_DELIVER;
}

enum tcpr_verdict tcpr_update(struct tcpr *t, struct tcpr *u)
{
	uint32_t ack = t->hard.ack;

	if (!u->port) {
		memcpy(u, t, sizeof(*u));
		return TCPR_DELIVER;
	}

	memcpy(&t->hard, &u->hard, sizeof(t->hard));
	t->port = u->port;
	t->done = u->done;
	t->failed = u->failed;
	if (t->hard.ack != ack)
		return TCPR_ACKNOWLEDGE;
	if (u->failed)
		return TCPR_RESET;
	return TCPR_DROP;
}

void tcpr_acknowledge(struct tcphdr *h, struct tcpr *t)
{
	if (t->hard.done_reading) {
		t->hard.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->hard.ack)
			t->done = 1;
	}

	memset(h, 0, sizeof(*h));
	h->source = t->hard.port;
	h->dest = t->hard.peer.port;
	h->seq = htonl(ntohl(t->seq) - t->delta);
	h->ack_seq = t->hard.ack;
	h->doff = sizeof(*h) / 4;
	h->ack = 1;
	h->window = t->win;
}

void tcpr_recover(struct tcphdr *h, struct tcpr *t)
{
	uint8_t *opt = (uint8_t *)(h + 1);
	size_t i = 0;

	memset(h, 0, sizeof(*h));
	h->source = t->hard.peer.port;
	h->dest = t->port;
	h->seq = htonl(ntohl(t->hard.ack) - 1);
	h->ack_seq = t->seq;
	h->doff = sizeof(*h) / 4;
	h->syn = 1;
	h->ack = 1;
	h->window = t->peer.win;

	if (t->hard.peer.mss) {
		opt[i++] = TCPOPT_MSS;
		opt[i++] = 4;
		opt[i++] = t->hard.peer.mss >> 8;
		opt[i++] = t->hard.peer.mss & 0xff;
	}

	if (t->hard.peer.ws) {
		opt[i++] = TCPOPT_WINDOW;
		opt[i++] = 3;
		opt[i++] = t->hard.peer.ws - 1;
	}

	if (t->hard.peer.sack_permitted) {
		opt[i++] = TCPOPT_SACK_PERM;
		opt[i++] = 2;
	}

	if (i % 4)
		opt[i++] = TCPOPT_EOL;
	h->doff += (i + 3) / 4;
}

void tcpr_reset(struct tcphdr *h, struct tcpr *t)
{
	memset(h, 0, sizeof(*h));
	h->source = t->hard.peer.port;
	h->dest = t->port;
	h->seq = t->ack;
	h->doff = sizeof(*h) / 4;
	h->rst = 1;
}
