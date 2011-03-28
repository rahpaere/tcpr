#include "tcpr.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

#define CLOSING_FLAGS (TCPR_HAVE_PEER_ACK | TCPR_HAVE_PEER_FIN \
			| TCPR_HAVE_ACK | TCPR_HAVE_FIN)

static uint32_t shorten(uint32_t n)
{
	return (n >> 16) + (n & 0xffff);
}

int tcpr_handle_segment_from_peer(struct tcpr_state *state, struct tcphdr *tcp,
					size_t size)
{
	uint32_t sum = tcp->th_sum ^ 0xffff;
	uint8_t *end = (uint8_t *)((uint32_t *)tcp + tcp->th_off);
	uint8_t *option = (uint8_t *)(tcp + 1);
	uint8_t *tmp;
	int flags = 0;

	while (option < end && *option != TCPOPT_EOL)
		switch (*option) {
		case TCPOPT_NOP:
			option++;
			break;
		case TCPOPT_MAXSEG:
			state->peer_mss = (uint16_t)option[2] << 8 | option[3];
			state->flags |= TCPR_HAVE_PEER_MSS;
			option += option[1];
			break;
		case TCPOPT_WINDOW:
			state->peer_ws = option[2];
			state->flags |= TCPR_HAVE_PEER_WS;
			option += option[1];
			break;
		case TCPOPT_TIMESTAMP:
			option += option[1];
			break;
		default:
			tcp->th_sum = 0;
			for (tmp = option + option[1]; option != tmp; option++)
				*option = TCPOPT_NOP;
			break;
		}

	state->peer_win = tcp->th_win;

	if (tcp->th_flags & TH_SYN) {
		state->delta = 0;
		state->ack = htonl(ntohl(tcp->th_seq) + 1);
		state->flags |= TCPR_HAVE_ACK;
	}

	if (tcp->th_flags & TH_FIN) {
		state->peer_fin = htonl(ntohl(tcp->th_seq)
					+ ((tcp->th_flags & TH_SYN) ? 1 : 0) + 1
					+ size - tcp->th_off * 4);
		state->flags |= TCPR_HAVE_PEER_FIN;
	}

	if (tcp->th_flags & TH_ACK) {
		if (!(state->flags & TCPR_HAVE_PEER_ACK))
			flags |= TCPR_PEER_ACK;

		state->peer_ack = tcp->th_ack;
		state->flags |= TCPR_HAVE_PEER_ACK;

		if (!(state->flags & TCPR_HAVE_ACK))
			return TCPR_NO_STATE | flags;

		if ((state->flags & CLOSING_FLAGS) == CLOSING_FLAGS
				&& state->peer_ack == state->fin
				&& state->peer_fin == state->ack)
			flags |= TCPR_CLOSING;

		sum += shorten(~tcp->th_ack);
		tcp->th_ack = htonl(ntohl(tcp->th_ack) + state->delta);
		sum += shorten(tcp->th_ack);

		if (tcp->th_sum)
			tcp->th_sum = ~shorten(shorten(sum));
	}

	return flags;
}

int tcpr_handle_segment(struct tcpr_state *state, struct tcphdr *tcp,
				size_t size)
{
	uint32_t sum = tcp->th_sum ^ 0xffff;
	int flags = 0;
	uint8_t *end = (uint8_t *)((uint32_t *)tcp + tcp->th_off);
	uint8_t *option = (uint8_t *)(tcp + 1);
	uint8_t *tmp;

	while (option < end && *option != TCPOPT_EOL)
		switch (*option) {
		case TCPOPT_NOP:
			option++;
			break;
		case TCPOPT_MAXSEG:
		case TCPOPT_WINDOW:
		case TCPOPT_TIMESTAMP:
			option += option[1];
			break;
		default:
			tcp->th_sum = 0;
			for (tmp = option + option[1]; option != tmp; option++)
				*option = TCPOPT_NOP;
			break;
		}

	if (tcp->th_flags & TH_RST)
		return TCPR_SPURIOUS_RST;

	state->win = tcp->th_win;
	state->seq = htonl(ntohl(tcp->th_seq)
			+ ((tcp->th_flags & TH_SYN) ? 1 : 0)
			+ size - tcp->th_off * 4);

	if (tcp->th_flags & TH_FIN) {
		if (!(state->flags & TCPR_DONE_WRITING))
			return TCPR_SPURIOUS_FIN;
		state->fin = htonl(ntohl(state->seq) + 1 - state->delta);
		state->flags |= TCPR_HAVE_FIN;
	}

	if (!(tcp->th_flags & TH_ACK)) {
		if (!(state->flags & TCPR_HAVE_PEER_ACK))
			return 0;
		state->delta = ntohl(state->seq) - ntohl(state->peer_ack);
		state->flags &= ~TCPR_DONE_WRITING;
		return TCPR_RECOVERY;
	}

	state->raw_ack = tcp->th_ack;
	if (state->flags & TCPR_DONE_READING) {
		state->ack = state->raw_ack;
		state->flags |= TCPR_HAVE_ACK;
		if ((state->flags & CLOSING_FLAGS) == CLOSING_FLAGS
				&& state->peer_ack == state->fin
				&& state->peer_fin == state->ack)
			flags |= TCPR_CLOSING;
	} else {
		if (!(state->flags & TCPR_HAVE_ACK))
			return TCPR_NO_STATE;
		if (tcp->th_ack != state->ack) {
			if (size == (size_t)tcp->th_off * 4)
				return TCPR_DUPLICATE_ACK;
			sum += shorten(~tcp->th_ack);
			tcp->th_ack = state->ack;
			sum += shorten(tcp->th_ack);
		}
	}

	sum += shorten(~tcp->th_seq);
	tcp->th_seq = htonl(ntohl(tcp->th_seq) - state->delta);
	sum += shorten(tcp->th_seq);

	if (tcp->th_sum)
		tcp->th_sum = ~shorten(shorten(sum));
	return flags;
}

void tcpr_make_acknowledgment(struct tcphdr *tcp, struct tcpr_state *state)
{
	tcp->th_sport = state->port;
	tcp->th_dport = state->peer_port;
	tcp->th_seq = htonl(ntohl(state->seq) - state->delta);
	tcp->th_ack = state->ack;
	tcp->th_off = sizeof(*tcp) / 4;
	tcp->th_x2 = 0;
	tcp->th_flags = TH_ACK;
	tcp->th_win = state->win; /* FIXME: zero window */
	tcp->th_sum = 0;
	tcp->th_urp = 0;
}

void tcpr_make_handshake(struct tcphdr *tcp, struct tcpr_state *state)
{
	uint8_t *option = (uint8_t *)(tcp + 1);
	size_t i = 0;

	tcp->th_sport = state->peer_port;
	tcp->th_dport = state->port;
	tcp->th_seq = htonl(ntohl(state->ack) - 1);
	tcp->th_ack = state->seq;
	tcp->th_off = sizeof(*tcp) / 4;
	tcp->th_x2 = 0;
	tcp->th_flags = TH_SYN | TH_ACK;
	tcp->th_win = state->peer_win;
	tcp->th_sum = 0;
	tcp->th_urp = 0;

	if (state->flags & TCPR_HAVE_PEER_MSS) {
		option[i++] = TCPOPT_MAXSEG;
		option[i++] = 4;
		option[i++] = state->peer_mss >> 8;
		option[i++] = state->peer_mss & 0xff;
	}

	if (state->flags & TCPR_HAVE_PEER_WS) {
		option[i++] = TCPOPT_WINDOW;
		option[i++] = 3;
		option[i++] = state->peer_ws;
	}

	if (i % 4)
		option[i++] = TCPOPT_EOL;
	tcp->th_off += (i + 3) / 4;
}

void tcpr_make_reset(struct tcphdr *tcp, struct tcpr_state *state)
{
	tcp->th_sport = state->peer_port;
	tcp->th_dport = state->port;
	tcp->th_seq = state->raw_ack;
	tcp->th_ack = 0;
	tcp->th_off = sizeof(*tcp) / 4;
	tcp->th_x2 = 0;
	tcp->th_flags = TH_RST;
	tcp->th_win = state->peer_win;
	tcp->th_sum = 0;
	tcp->th_urp = 0;
}

int tcpr_handle_update(struct tcpr_state *state, struct tcpr_update *update)
{
	int flags = 0;

	if (update->flags & TCPR_TIME_WAIT)
		return TCPR_CLOSED;
	if ((update->flags & TCPR_DONE_READING) &&
			(state->flags & TCPR_HAVE_ACK))
		update->ack = state->raw_ack;
	if (update->ack != state->ack)
		flags |= TCPR_UPDATE_ACK;

	state->peer_mss = update->peer_mss;
	state->peer_ws = update->peer_ws;
	state->ack = update->ack;
	state->delta = update->delta;
	state->flags |= update->flags;

	if ((state->flags & CLOSING_FLAGS) == CLOSING_FLAGS
			&& state->peer_ack == state->fin
			&& state->peer_fin == state->ack)
		flags |= TCPR_CLOSING;

	return flags;
}

void tcpr_make_update(struct tcpr_update *update, struct tcpr_state *state)
{
	update->peer_port = state->peer_port;
	update->port = state->port;
	update->peer_ack = state->peer_ack;
	update->peer_mss = state->peer_mss;
	update->peer_ws = state->peer_ws;
	update->ack = state->ack;
	update->delta = state->delta;
	update->flags = state->flags & TCPR_HAVE_ACK;
	if ((state->flags & CLOSING_FLAGS) == CLOSING_FLAGS
			&& state->peer_ack == state->fin
			&& state->peer_fin == state->ack)
		update->flags |= TCPR_TIME_WAIT;
}
