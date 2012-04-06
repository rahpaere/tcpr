#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/nsproxy.h>
#include <linux/netfilter/x_tables.h>
#include <net/route.h>

#include <tcpr/types.h>
#include <tcpr/filter.h>
#include <tcpr/module.h>

struct connection {
	struct list_head list;
	struct tcpr tcpr;
	struct net *net_ns;
	uint32_t address;
	uint32_t peer_address;
	atomic_t refcnt;
	spinlock_t tcpr_lock;
	wait_queue_head_t wait;
};

struct packet {
	struct iphdr ip;
	struct tcphdr tcp;
	char opts[40];
};

static rwlock_t connections_lock;
static struct list_head connections;

static struct cdev tcpr_cdev;
static dev_t tcpr_dev;

static struct connection *lookup_internal(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port,
					  struct net *net_ns)
{
	struct connection *c;

	printk(KERN_DEBUG "lookup_internal(%x, %x, %hu, %hu, %p)\n", htonl(address), htonl(peer_address), htons(port), htons(peer_port), net_ns);
 	list_for_each_entry(c, &connections, list) {
		printk(KERN_DEBUG "list entry (%x, %x, %hu, %hu, %p)\n", htonl(c->address), htonl(c->peer_address), htons(c->tcpr.saved.external_port), htons(c->tcpr.saved.peer.port), c->net_ns);
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.internal_port == port
		    && c->net_ns == net_ns)
			return c;
	}
	printk(KERN_DEBUG "no match.\n");
	return NULL;
}

static struct connection *lookup_external(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port,
					  struct net *net_ns)
{
	struct connection *c;

	printk(KERN_DEBUG "lookup_external(%x, %x, %hu, %hu, %p)\n", htonl(address), htonl(peer_address), htons(port), htons(peer_port), net_ns);
	list_for_each_entry(c, &connections, list) {
		printk(KERN_DEBUG "list entry (%x, %x, %hu, %hu, %p)\n", htonl(c->address), htonl(c->peer_address), htons(c->tcpr.saved.external_port), htons(c->tcpr.saved.peer.port), c->net_ns);
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.external_port == port
		    && c->net_ns == net_ns)
			return c;
	}
	printk(KERN_DEBUG "no match.\n");
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
	memset(&c->tcpr, 0, sizeof(c->tcpr));
	c->net_ns = net_ns;
	c->address = address;
	c->peer_address = peer_address;
	c->tcpr.saved.internal_port = port;
	c->tcpr.saved.external_port = port;
	c->tcpr.saved.peer.port = peer_port;
	atomic_set(&c->refcnt, 1);
	init_waitqueue_head(&c->wait);
	spin_lock_init(&c->tcpr_lock);
	list_add(&c->list, &connections);
	write_unlock(&connections_lock);
	return c;
}

static void connection_close(struct connection *c)
{
	if (!atomic_dec_and_test(&c->refcnt))
		return;
	write_lock(&connections_lock);
	list_del(&c->list);
	write_unlock(&connections_lock);
	kfree(c);
}

/* stolen from ip_finish_output2 */
static int output_finish(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	int res;

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	rcu_read_lock();
	if (dst->hh) {
		int res = neigh_hh_output(dst->hh, skb);

		rcu_read_unlock();
		return res;
	} else {
		neigh = dst_get_neighbour(dst);
		if (neigh) {
			res = neigh->output(skb);

			rcu_read_unlock();
			return res;
		}
		rcu_read_unlock();
	}

	if (net_ratelimit())
		printk(KERN_DEBUG "TCPR output: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

static int output_skb(struct net *net_ns, struct packet *packet)
{
	struct sk_buff *skb;
	struct rtable *rt;

	skb = alloc_skb(LL_MAX_HEADER + packet->ip.tot_len, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_DEBUG "TCPR cannot allocate SKB\n");
		return -1;
	}

	skb->ip_summed = CHECKSUM_NONE;
	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, packet->ip.tot_len);
	memcpy(skb->data, packet, packet->ip.tot_len);

	rt = ip_route_output(net_ns, packet->ip.daddr, packet->ip.saddr, RT_TOS(packet->ip.tos), 0);
	if (!rt) {
		printk(KERN_DEBUG "TCPR cannot route\n");
		kfree(skb);
		return -1;
	}

	skb_dst_set(skb, &rt->dst);
	skb->dev = skb_dst(skb)->dev;
	skb->protocol = htons(ETH_P_IP);
	return dst_output(skb);
}

static void inject(struct connection *c, int mode)
{
	struct packet packet;

	memset(&packet, 0, sizeof(packet));
	packet.ip.ihl = sizeof(packet.ip) / 4;
	packet.ip.version = 4;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_TCP;

	switch (mode) {
	case TCPR_RESET:
		tcpr_reset(&packet.tcp, &c->tcpr);
		packet.ip.saddr = c->peer_address;
		packet.ip.daddr = c->address;
		break;

	case TCPR_RECOVER:
		tcpr_recover(&packet.tcp, &c->tcpr);
		packet.ip.saddr = c->peer_address;
		packet.ip.daddr = c->address;
		break;

	default:
		tcpr_update(&packet.tcp, &c->tcpr);
		packet.ip.saddr = c->address;
		packet.ip.daddr = c->peer_address;
	}

	packet.ip.tot_len = htons(sizeof(packet.ip) + packet.tcp.doff * 4);
        packet.ip.check = ip_fast_csum(&packet.ip, packet.ip.ihl);
	packet.tcp.check = csum_tcpudp_magic(packet.ip.saddr, packet.ip.daddr,
					     sizeof(packet.tcp), IPPROTO_TCP,
					     csum_partial(&packet.tcp,
							  sizeof(packet.tcp),
							  0));

	output_skb(c->net_ns, &packet);
}

static int tcpr_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Opened TCPR handle.\n");
	file->private_data = NULL;
	return 0;
}

static int tcpr_release(struct inode *inode, struct file *file)
{
	struct connection *c = file->private_data;

	if (c != NULL)
		connection_close(c);
	printk(KERN_INFO "Closed TCPR handle.\n");
	return 0;
}

static int test_done(struct connection *c)
{
	return c->tcpr.done;
}

static long tcpr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct connection *c = file->private_data;
	int ret;

	if (cmd == TCPR_ATTACH) {
		struct tcpr_connection tc;

		if (c != NULL)
			return -EEXIST;
		
		ret = copy_from_user(&tc, (struct tcpr_connection __user *)arg,
				     sizeof(tc));
		if (ret)
			return ret;

		c = connection_create(tc.address, tc.peer_address, tc.port,
				      tc.peer_port, current->nsproxy->net_ns);
		if (!c)
			return -ENOMEM;

		file->private_data = c;
		atomic_inc(&c->refcnt);
		printk(KERN_DEBUG "TCPR_ATTACH\n");
		return 0;
	} else if (c == NULL) {
		return -ENOENT;
	}

	spin_lock(&c->tcpr_lock);
	switch (cmd) {
	case TCPR_GET:
		ret = copy_to_user((struct tcpr __user *)arg,
				   &c->tcpr, sizeof(c->tcpr));
		if (ret) {
			spin_unlock(&c->tcpr_lock);
			return ret;
		}
		printk(KERN_DEBUG "TCPR_GET\n");
		break;

	case TCPR_ACK:
		c->tcpr.saved.ack = htonl(ntohl(c->tcpr.saved.ack) + arg);
		inject(c, 0);
		printk(KERN_DEBUG "TCPR_ACK %ld\n", arg);
		break;
		
	case TCPR_DONE_READING:
		c->tcpr.saved.done_reading = 1;
		printk(KERN_DEBUG "TCPR_DONE_READING\n");
		break;

	case TCPR_DONE_WRITING:
		c->tcpr.saved.done_writing = 1;
		printk(KERN_DEBUG "TCPR_DONE_WRITING\n");
		break;

	case TCPR_CLOSE:
		c->tcpr.saved.done_reading = 1;
		c->tcpr.saved.done_writing = 1;
		printk(KERN_DEBUG "TCPR_CLOSE\n");
		break;

	case TCPR_KILL:
		inject(c, TCPR_RESET);
		printk(KERN_DEBUG "TCPR_KILL\n");
		break;

	case TCPR_WAIT:
		spin_unlock(&c->tcpr_lock);
		printk(KERN_DEBUG "entering TCPR_WAIT\n");
		wait_event_interruptible(c->wait, test_done(c));
		printk(KERN_DEBUG "TCPR_WAIT\n");
		return 0;

	case TCPR_DONE:
		if (!c->tcpr.done) {
			c->tcpr.done = 1;
			wake_up_interruptible(&c->wait);
			connection_close(c);
		}
		printk(KERN_DEBUG "TCPR_DONE\n");
		break;

	default:
		spin_unlock(&c->tcpr_lock);
		return -ENOIOCTLCMD;
	}

	spin_unlock(&c->tcpr_lock);
	return 0;
}

static unsigned int tcpr_tg_application(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	unsigned int verdict = NF_DROP;
	int done;
	int mode;

	ip = ip_hdr(skb);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	
	printk(KERN_DEBUG "TCPR packet from application (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);

	read_lock(&connections_lock);
	c = lookup_internal(ip->saddr, ip->daddr, tcp->source, tcp->dest, net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;
		c = connection_create(ip->saddr, ip->daddr,
				      tcp->source, tcp->dest, net_ns);
		if (!c)
			return NF_DROP;
	}
	if (!c) {
		printk(KERN_DEBUG "No TCPR connection for application packet.\n");
		return verdict;
	}

	spin_lock(&c->tcpr_lock);
	done = c->tcpr.done;
	printk(KERN_DEBUG "Before filtering, ack = %u (%u)\n", ntohl(c->tcpr.saved.ack), ntohl(c->tcpr.ack));
	mode = tcpr_filter(&c->tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	if (mode == TCPR_DELIVER)
		verdict = NF_ACCEPT;
	else if (mode != TCPR_DROP)
		inject(c, mode);
	if (c->tcpr.done && !done) {
		printk(KERN_DEBUG "Connection is now done.\n");
		wake_up_interruptible(&c->wait);
		connection_close(c);
	}
	printk(KERN_DEBUG "After filtering, ack = %u (%u)\n", ntohl(c->tcpr.saved.ack), ntohl(c->tcpr.ack));
	printk(KERN_DEBUG "Done with this packet.\n");
	spin_unlock(&c->tcpr_lock);
	return verdict;
}

static unsigned int tcpr_tg_peer(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	int done;

	ip = ip_hdr(skb);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	printk(KERN_DEBUG "TCPR packet from peer (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);


	read_lock(&connections_lock);
	c = lookup_external(ip->daddr, ip->saddr, tcp->dest, tcp->source, net_ns);
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
	done = c->tcpr.done;
	printk(KERN_DEBUG "Before filtering, ack = %u (%u)\n", ntohl(c->tcpr.saved.ack), ntohl(c->tcpr.ack));
	tcpr_filter_peer(&c->tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	printk(KERN_DEBUG "Delivering packet.\n");
	if (c->tcpr.done && !done) {
		printk(KERN_DEBUG "Connection is now done.\n");
		wake_up_interruptible(&c->wait);
		connection_close(c);
	}
	printk(KERN_DEBUG "After filtering, ack = %u (%u)\n", ntohl(c->tcpr.saved.ack), ntohl(c->tcpr.ack));
	printk(KERN_DEBUG "Done with this packet.\n");
	spin_unlock(&c->tcpr_lock);
	return NF_ACCEPT;
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

static struct xt_target tcpr_tg_regs = {
	.name = "TCPR",
	.revision = 0,
	.family = AF_INET,
	.table = "mangle",
	.proto = IPPROTO_TCP,
	.target = tcpr_tg,
	.targetsize = sizeof(int),
	.me = THIS_MODULE,
};

static struct file_operations tcpr_fops = {
	.open = tcpr_open,
	.release = tcpr_release,
	.unlocked_ioctl = tcpr_ioctl,
	.owner = THIS_MODULE,
};

static int __init tcpr_tg_init(void)
{
	int ret;

	rwlock_init(&connections_lock);
	INIT_LIST_HEAD(&connections);

	ret = alloc_chrdev_region(&tcpr_dev, 0, 1, "tcpr");
	if (ret < 0) {
		printk(KERN_ERR "Unable to register TCPR device region\n");
		return ret;
	}

	cdev_init(&tcpr_cdev, &tcpr_fops);
	ret = cdev_add(&tcpr_cdev, tcpr_dev, 1);
	if (ret < 0) {
		printk(KERN_ERR "Unable to add TCPR device\n");
		unregister_chrdev_region(tcpr_dev, 1);
		return ret;
	}

	ret = xt_register_target(&tcpr_tg_regs);
	if (ret < 0) {
		printk(KERN_ERR "Unable to register TCPR Xtables target\n");
		cdev_del(&tcpr_cdev);
		unregister_chrdev_region(tcpr_dev, 1);
	}

	printk(KERN_INFO "TCPR loaded with major %u and minor %u.\n", MAJOR(tcpr_dev), MINOR(tcpr_dev));
	return 0;
}

static void __exit tcpr_tg_exit(void)
{
	xt_unregister_target(&tcpr_tg_regs);
	cdev_del(&tcpr_cdev);
	unregister_chrdev_region(tcpr_dev, 1);
	printk(KERN_INFO "TCPR unloaded\n");
}

module_init(tcpr_tg_init);
module_exit(tcpr_tg_exit);

MODULE_AUTHOR("Robert Surton <burgess@cs.cornell.edu>");
MODULE_DESCRIPTION("Xtables: TCPR target");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("ipt_tcpr");
