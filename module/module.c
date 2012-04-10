#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/nsproxy.h>
#include <linux/netfilter/x_tables.h>
#include <net/route.h>
#include <net/ip.h>

#include <tcpr/types.h>
#include <tcpr/filter.h>

struct connection {
	struct list_head list;
	struct tcpr_ip4 state;
	struct net *net_ns;
	spinlock_t tcpr_lock;
};

static rwlock_t connections_lock;
static struct list_head connections;

static struct connection *lookup_internal(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port,
					  struct net *net_ns)
{
	struct connection *c;

 	list_for_each_entry(c, &connections, list)
		if (c->state.peer_address == peer_address
		    && c->state.address == address
		    && c->state.tcpr.hard.peer.port == peer_port
		    && c->state.tcpr.port == port
		    && c->net_ns == net_ns)
			return c;
	return NULL;
}

static struct connection *lookup_external(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port,
					  struct net *net_ns)
{
	struct connection *c;

	list_for_each_entry(c, &connections, list)
		if (c->state.peer_address == peer_address
		    && c->state.address == address
		    && c->state.tcpr.hard.peer.port == peer_port
		    && c->state.tcpr.hard.port == port
		    && c->net_ns == net_ns)
			return c;
	return NULL;
}

static struct connection *connection_create(uint32_t address,
					    uint32_t peer_address,
					    uint16_t port,
					    uint16_t peer_port,
					    struct net *net_ns)
{
	struct connection *c;

	write_lock(&connections_lock);
	c = lookup_external(address, peer_address, port, peer_port, net_ns);
	if (c != NULL) {
		write_unlock(&connections_lock);
		return c;
	}

	c = kmalloc(sizeof(*c), GFP_ATOMIC);
	if (!c) {
		write_unlock(&connections_lock);
		return NULL;
	}

	INIT_LIST_HEAD(&c->list);
	memset(&c->state.tcpr, 0, sizeof(c->state.tcpr));
	c->state.address = address;
	c->state.peer_address = peer_address;
	c->net_ns = net_ns;
//	c->state.tcpr.hard.peer.port = peer_port;
//	c->state.tcpr.hard.port = port;
//	c->state.tcpr.port = port;
	spin_lock_init(&c->tcpr_lock);
	list_add(&c->list, &connections);
	write_unlock(&connections_lock);
	return c;
}

static void connection_done(struct connection *c)
{
	write_lock(&connections_lock);
	list_del(&c->list);
	write_unlock(&connections_lock);
	kfree(c);
}

static void inject_ip(struct iphdr *ip, struct sk_buff *oldskb)
{
	struct sk_buff *skb;

	printk(KERN_DEBUG "TCPR inject_ip %d + %d bytes\n", LL_MAX_HEADER, ntohs(ip->tot_len));
	skb = alloc_skb(LL_MAX_HEADER + ntohs(ip->tot_len), GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_DEBUG "TCPR cannot allocate SKB\n");
		return;
	}

	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, ntohs(ip->tot_len));
	memcpy(skb->data, ip, ntohs(ip->tot_len));
	skb_dst_set(skb, dst_clone(skb_dst(oldskb)));
	if (ip_route_me_harder(skb, RTN_UNSPEC) < 0) {
		printk(KERN_DEBUG "TCPR cannot route\n");
		kfree_skb(skb);
		return;
	}
	
	ip_hdr(skb)->ttl = dst_metric(skb_dst(skb), RTAX_HOPLIMIT);
	skb->ip_summed = CHECKSUM_NONE;
	if (skb->len > dst_mtu(skb_dst(skb))) {
		printk(KERN_DEBUG "TCPR generated packet that would fragment\n");
		kfree_skb(skb);
		return;
	}

	ip_local_out(skb);
}

static void inject_tcp(struct connection *c, enum tcpr_verdict tcpr_verdict, struct sk_buff *oldskb)
{
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
		char opts[40];
	} packet;

	memset(&packet, 0, sizeof(packet));
	packet.ip.ihl = sizeof(packet.ip) / 4;
	packet.ip.version = 4;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_TCP;

	switch (tcpr_verdict) {
	case TCPR_RESET:
		printk(KERN_DEBUG "TCPR reset\n");
		tcpr_reset(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->state.peer_address;
		packet.ip.daddr = c->state.address;
		break;

	case TCPR_RECOVER:
		printk(KERN_DEBUG "TCPR recover\n");
		tcpr_recover(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->state.peer_address;
		packet.ip.daddr = c->state.address;
		break;

	default:
		printk(KERN_DEBUG "TCPR acknowledge\n");
		tcpr_acknowledge(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->state.address;
		packet.ip.daddr = c->state.peer_address;
	}

	packet.ip.tot_len = htons(sizeof(packet.ip) + packet.tcp.doff * 4);
        packet.ip.check = ip_fast_csum(&packet.ip, packet.ip.ihl);
	packet.tcp.check = csum_tcpudp_magic(packet.ip.saddr, packet.ip.daddr,
					     sizeof(packet.tcp), IPPROTO_TCP,
					     csum_partial(&packet.tcp,
							  sizeof(packet.tcp),
							  0));

	inject_ip(&packet.ip, oldskb);
}

static void inject_update(struct iphdr *ip, struct udphdr *udp, struct tcpr_ip4 *state, struct sk_buff *oldskb)
{
	struct {
		struct iphdr ip;
		struct udphdr udp;
		struct tcpr_ip4 state;
	} packet;

	printk(KERN_DEBUG "TCPR update\n");
	memset(&packet, 0, sizeof(packet));
	packet.ip.ihl = sizeof(packet.ip) / 4;
	packet.ip.version = 4;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.tot_len = htons(sizeof(packet));
        packet.ip.check = ip_fast_csum(&packet.ip, packet.ip.ihl);
	packet.ip.saddr = ip->daddr;
	packet.ip.daddr = ip->saddr;
	packet.udp.source = udp->dest;
	packet.udp.dest = udp->source;
	packet.udp.len = htons(sizeof(packet.udp) + sizeof(packet.state));
	packet.udp.check = 0;
	memcpy(&packet.state, state, sizeof(packet.state));
	inject_ip(&packet.ip, oldskb);
}

static unsigned int tcpr_tg_update(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct tcpr_ip4 *update;
	struct connection *c;
	enum tcpr_verdict tcpr_verdict;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_UDP)
		return NF_DROP;
	udp = (struct udphdr *)((uint32_t *)ip + ip->ihl);
	update = (struct tcpr_ip4 *)(udp + 1);

	printk(KERN_DEBUG "TCPR received update\n");

	read_lock(&connections_lock);
	c = lookup_external(update->address, update->peer_address,
			    update->tcpr.hard.port, update->tcpr.hard.peer.port,
			    net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (!update->tcpr.port) {
			inject_update(ip, udp, update, skb);
			return NF_DROP;
		}
		c = connection_create(update->address, update->peer_address,
				      update->tcpr.hard.port,
				      update->tcpr.hard.peer.port, net_ns);
		if (!c)
			return NF_DROP;
	}

	spin_lock(&c->tcpr_lock);
	tcpr_verdict = tcpr_update(&c->state.tcpr, &update->tcpr);
	if (tcpr_verdict == TCPR_DELIVER) {
		inject_update(ip, udp, update, skb);
	} else if (tcpr_verdict != TCPR_DROP) {
		inject_tcp(c, tcpr_verdict, skb);
	} else {
		printk(KERN_DEBUG "Dropping update.\n");
	}
	if (c->state.tcpr.done) {
		printk(KERN_DEBUG "Connection is done.\n");
		connection_done(c);
	}
	spin_unlock(&c->tcpr_lock);
	return NF_DROP;
}

static unsigned int tcpr_tg_application(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	enum tcpr_verdict tcpr_verdict;
	unsigned int verdict = NF_DROP;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_TCP)
		return tcpr_tg_update(skb, net_ns);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	printk(KERN_DEBUG "TCPR received packet from application (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);
	
	read_lock(&connections_lock);
	c = lookup_internal(ip->saddr, ip->daddr, tcp->source, tcp->dest,
			    net_ns);
	read_unlock(&connections_lock);
	if (!c)
		return NF_DROP;

	spin_lock(&c->tcpr_lock);
	tcpr_verdict = tcpr_filter(&c->state.tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	if (tcpr_verdict == TCPR_DELIVER)
		verdict = NF_ACCEPT;
	else if (tcpr_verdict != TCPR_DROP)
		inject_tcp(c, tcpr_verdict, skb);
	if (c->state.tcpr.done)
		connection_done(c);
	spin_unlock(&c->tcpr_lock);
	return verdict;
}

static unsigned int tcpr_tg_peer(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	enum tcpr_verdict tcpr_verdict;
	unsigned int verdict = NF_DROP;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_TCP)
		return NF_DROP;
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	printk(KERN_DEBUG "TCPR received packet from peer (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);

	read_lock(&connections_lock);
	c = lookup_external(ip->daddr, ip->saddr, tcp->dest, tcp->source,
			    net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;
		c = connection_create(ip->daddr, ip->saddr,
				      tcp->dest, tcp->source, net_ns);
		if (!c)
			return NF_DROP;
	}

	spin_lock(&c->tcpr_lock);
	tcpr_verdict = tcpr_filter_peer(&c->state.tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	if (tcpr_verdict == TCPR_DELIVER)
		verdict = NF_ACCEPT;
	else if (tcpr_verdict != TCPR_DROP)
		inject_tcp(c, tcpr_verdict, skb);
	if (c->state.tcpr.done)
		connection_done(c);
	spin_unlock(&c->tcpr_lock);
	return verdict;
}

static unsigned int tcpr_tg(struct sk_buff *skb,
			    const struct xt_action_param *par)
{
	const int *peer = par->targinfo;
	struct net *net_ns = dev_net(par->in ? par->in : par->out);

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	if (*peer)
		return tcpr_tg_peer(skb, net_ns);
	else
		return tcpr_tg_application(skb, net_ns);
}

static struct xt_target tcpr_tg_reg = {
	.name = "TCPR",
	.family = AF_INET,
	.target = tcpr_tg,
	.targetsize = sizeof(int),
	.me = THIS_MODULE,
};

static int __init tcpr_tg_init(void)
{
	rwlock_init(&connections_lock);
	INIT_LIST_HEAD(&connections);
	return xt_register_target(&tcpr_tg_reg);
}

static void __exit tcpr_tg_exit(void)
{
	xt_unregister_target(&tcpr_tg_reg);
}

module_init(tcpr_tg_init);
module_exit(tcpr_tg_exit);

MODULE_AUTHOR("Robert Surton <burgess@cs.cornell.edu>");
MODULE_DESCRIPTION("Xtables: TCPR target");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("ipt_tcpr");
