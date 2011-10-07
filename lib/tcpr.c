#include <tcpr/filter.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

static uint32_t shorten(uint32_t n)
{
	return (n >> 16) + (n & 0xffff);
}

enum tcpr_verdict tcpr_filter(struct tcpr *t, struct tcphdr *h, size_t size)
{
	uint32_t sum = h->th_sum ^ 0xffff;
	uint8_t *end = (uint8_t *)((uint32_t *)h + h->th_off);
	uint8_t *opt = (uint8_t *)(h + 1);
	uint8_t *tmp;

	while (opt < end && *opt != TCPOPT_EOL)
		switch (*opt) {
		case TCPOPT_NOP:
			opt++;
			break;
		case TCPOPT_MAXSEG:
		case TCPOPT_MD5:
		case TCPOPT_SACK:
		case TCPOPT_SACK_PERMITTED:
		case TCPOPT_TIMESTAMP:
		case TCPOPT_WINDOW:
			opt += opt[1];
			break;
		default:
			h->th_sum = 0;
			for (tmp = opt + opt[1]; opt != tmp; opt++)
				*opt = TCPOPT_NOP;
			break;
		}

	if (h->th_flags & TH_RST)
		return TCPR_DROP;

	t->win = h->th_win;
	t->seq =
	    htonl(ntohl(h->th_seq) + ((h->th_flags & TH_SYN) ? 1 : 0) + size -
		  h->th_off * 4);

	if (h->th_flags & TH_FIN) {
		t->fin = htonl(ntohl(t->seq) + 1 - t->delta);
		t->have_fin = 1;
	}

	if (h->th_flags & TH_SYN) {
		if (h->th_flags & TH_ACK) {
			t->saved.safe = htonl(ntohl(h->th_seq) + 1);
		} else if (!t->peer.have_ack) {
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

	t->ack = h->th_ack;
	if (t->saved.done_reading) {
		t->saved.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
			t->done = 1;
	} else if (h->th_ack != t->saved.ack) {
		if (size == (size_t)h->th_off * 4)
			return TCPR_DROP;
		sum += shorten(~h->th_ack);
		h->th_ack = t->saved.ack;
		sum += shorten(h->th_ack);
	}

	sum += shorten(~h->th_seq);
	h->th_seq = htonl(ntohl(h->th_seq) - t->delta);
	sum += shorten(h->th_seq);

	if (h->th_sum)
		h->th_sum = ~shorten(shorten(sum));
	return TCPR_DELIVER;
}

void tcpr_filter_peer(struct tcpr *t, struct tcphdr *h, size_t size)
{
	uint32_t sum = h->th_sum ^ 0xffff;
	uint8_t *end = (uint8_t *)((uint32_t *)h + h->th_off);
	uint8_t *opt = (uint8_t *)(h + 1);
	uint8_t *tmp;
	uint32_t sack;

	while (opt < end && *opt != TCPOPT_EOL)
		switch (*opt) {
		case TCPOPT_NOP:
			opt++;
			break;
		case TCPOPT_MAXSEG:
			t->saved.peer.mss = (uint16_t)opt[2] << 8 | opt[3];
			opt += opt[1];
			break;
		case TCPOPT_WINDOW:
			t->saved.peer.ws = opt[2] + 1;
			opt += opt[1];
			break;
		case TCPOPT_SACK_PERMITTED:
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
		case TCPOPT_MD5:
		case TCPOPT_TIMESTAMP:
			opt += opt[1];
			break;
		default:
			h->th_sum = 0;
			for (tmp = opt + opt[1]; opt != tmp; opt++)
				*opt = TCPOPT_NOP;
			break;
		}

	t->peer.win = h->th_win;

	if (h->th_flags & TH_SYN) {
		t->saved.ack = htonl(ntohl(h->th_seq) + 1);
		if (h->th_flags & TH_ACK)
			t->saved.safe = h->th_ack;
	}

	if (h->th_flags & TH_FIN) {
		t->peer.fin =
		    htonl(ntohl(h->th_seq) + ((h->th_flags & TH_SYN) ? 1 : 0) +
			  1 + size - h->th_off * 4);
		t->peer.have_fin = 1;
	}

	if (h->th_flags & TH_ACK) {
		if (!(h->th_flags & TH_RST)) {
			t->peer.ack = h->th_ack;
			t->peer.have_ack = 1;
			if (t->have_fin && t->peer.have_fin && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
				t->done = 1;
		}

		sum += shorten(~h->th_ack);
		h->th_ack = htonl(ntohl(h->th_ack) + t->delta);
		sum += shorten(h->th_ack);

		if (h->th_sum)
			h->th_sum = ~shorten(shorten(sum));
	}
}

void tcpr_recover(struct tcphdr *h, struct tcpr *t)
{
	uint8_t *opt = (uint8_t *)(h + 1);
	size_t i = 0;

	h->th_seq = htonl(ntohl(t->saved.ack) - 1);
	h->th_ack = t->seq;
	h->th_off = sizeof(*h) / 4;
	h->th_x2 = 0;
	h->th_flags = TH_SYN | TH_ACK;
	h->th_win = t->peer.win;
	h->th_sum = 0;
	h->th_urp = 0;

	if (t->saved.peer.mss) {
		opt[i++] = TCPOPT_MAXSEG;
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
		opt[i++] = TCPOPT_SACK_PERMITTED;
		opt[i++] = 2;
	}

	if (i % 4)
		opt[i++] = TCPOPT_EOL;
	h->th_off += (i + 3) / 4;
}

void tcpr_update(struct tcphdr *h, struct tcpr *t)
{
	if (t->saved.done_reading) {
		t->saved.ack = t->ack;
		if (t->have_fin && t->peer.have_fin && t->peer.have_ack
		    && t->peer.ack == t->fin && t->peer.fin == t->saved.ack)
			t->done = 1;
	}

	h->th_seq = htonl(ntohl(t->seq) - t->delta);
	h->th_ack = t->saved.ack;
	h->th_off = sizeof(*h) / 4;
	h->th_x2 = 0;
	h->th_flags = TH_ACK;
	h->th_win = t->win;
	h->th_sum = 0;
	h->th_urp = 0;
}

void tcpr_reset(struct tcphdr *h, struct tcpr *t)
{
	h->th_seq = t->ack;
	h->th_ack = 0;
	h->th_off = sizeof(*h) / 4;
	h->th_x2 = 0;
	h->th_flags = TH_RST;
	h->th_win = t->peer.win;
	h->th_sum = 0;
	h->th_urp = 0;
}
