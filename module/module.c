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
	uint32_t address;
	uint32_t peer_address;
	atomic_t refcnt;
	spinlock_t tcpr_lock;
	wait_queue_head_t wait;
};

static rwlock_t connections_lock;
static struct list_head connections;

static struct cdev tcpr_cdev;
static dev_t tcpr_dev;

static struct connection *lookup_internal(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port)
{
	struct connection *c;

	printk(KERN_DEBUG "lookup_internal(%x, %x, %hu, %hu)\n", htonl(address), htonl(peer_address), htons(port), htons(peer_port));
 	list_for_each_entry(c, &connections, list) {
		printk(KERN_DEBUG "list entry (%x, %x, %hu, %hu)\n", htonl(c->address), htonl(c->peer_address), htons(c->tcpr.saved.external_port), htons(c->tcpr.saved.peer.port));
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.internal_port == port)
			return c;
	}
	printk(KERN_DEBUG "no match.\n");
	return NULL;
}

static struct connection *lookup_external(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port)
{
	struct connection *c;

	printk(KERN_DEBUG "lookup_external(%x, %x, %hu, %hu)\n", htonl(address), htonl(peer_address), htons(port), htons(peer_port));
	list_for_each_entry(c, &connections, list) {
		printk(KERN_DEBUG "list entry (%x, %x, %hu, %hu)\n", htonl(c->address), htonl(c->peer_address), htons(c->tcpr.saved.external_port), htons(c->tcpr.saved.peer.port));
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.external_port == port)
			return c;
	}
	printk(KERN_DEBUG "no match.\n");
	return NULL;
}

static struct connection *connection_create(uint32_t address,
					    uint32_t peer_address,
					    uint16_t port,
					    uint16_t peer_port)
{
	struct connection *c;

	write_lock(&connections_lock);
	c = lookup_external(address, peer_address, port, peer_port);
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

static int inject(struct sk_buff *skb)
{
	struct iphdr *ip = ip_hdr(skb);
	struct tcphdr *tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	struct rtable *rt;
	int ret;
	int len;

	len = ntohs(ip->tot_len) - ip->ihl * 4;
	ip->check = 0;
	tcp->check = 0;
	printk(KERN_DEBUG "inject, len = %d - %d = %d\n", ntohs(ip->tot_len), ip->ihl * 4, len);
	tcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, len, ip->protocol,
				       csum_partial(tcp, len, 0));
	printk(KERN_DEBUG "tcp->check = %hx\n", tcp->check);
	ip->check = ip_fast_csum(ip, ip->ihl);
	skb->ip_summed = CHECKSUM_NONE;
	printk(KERN_DEBUG "ip->check = %hx\n", ip->check);

	rt = ip_route_output(&init_net, ip->saddr, ip->daddr,
			     RT_TOS(ip->tos), 0);
	if (IS_ERR(rt))
		return -1;
	printk(KERN_DEBUG "routed!\n");

	skb_dst_set(skb, &rt->dst);
	skb->dev = rt->dst.dev;
	skb->protocol = htons(ETH_P_IP);
	printk(KERN_DEBUG "about to dst_output\n");
	ret = dst_output(skb);
	return 0;
	if (ret) {
		printk(KERN_DEBUG "dst_output failed\n");
		return ret;
	}
	return 0;
}

static void update(struct connection *c)
{
	struct sk_buff *skb;
	struct iphdr *ip;
	struct tcphdr *tcp;

	skb = alloc_skb(LL_MAX_HEADER + 60, GFP_ATOMIC);
	if (skb == NULL)
		return;

	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, 60);

	ip = ip_hdr(skb);
	ip->ihl = sizeof(*ip) / 4;
	ip->version = 4;
	ip->tos = 0;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = c->address;
	ip->daddr = c->peer_address;

	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	tcpr_update(tcp, &c->tcpr);

	ip->tot_len = htons(sizeof(*ip) + tcp->doff * 4);
	inject(skb);
}

static void reset(struct connection *c)
{
	struct sk_buff *skb;
	struct iphdr *ip;
	struct tcphdr *tcp;

	skb = alloc_skb(LL_MAX_HEADER + 60, GFP_ATOMIC);
	if (skb == NULL)
		return;

	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, 60);

	ip = ip_hdr(skb);
	ip->ihl = sizeof(*ip) / 4;
	ip->version = 4;
	ip->tos = 0;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = c->peer_address;
	ip->daddr = c->address;

	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	tcpr_reset(tcp, &c->tcpr);

	ip->tot_len = htons(sizeof(*ip) + tcp->doff * 4);
	inject(skb);
}

static void recover(struct connection *c)
{
	struct sk_buff *skb;
	struct iphdr *ip;
	struct tcphdr *tcp;

	skb = alloc_skb(LL_MAX_HEADER + 60, GFP_ATOMIC);
	if (skb == NULL)
		return;

	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, 60);

	ip = ip_hdr(skb);
	ip->ihl = sizeof(*ip) / 4;
	ip->version = 4;
	ip->tos = 0;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = c->peer_address;
	ip->daddr = c->address;

	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	tcpr_recover(tcp, &c->tcpr);

	ip->tot_len = htons(sizeof(*ip) + tcp->doff * 4);
	inject(skb);
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

		c = connection_create(tc.address, tc.peer_address, tc.port, tc.peer_port);
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
		update(c);
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
		reset(c);
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

static unsigned int tcpr_tg_application(struct sk_buff *skb)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	unsigned int verdict = NF_DROP;
	int done;

	ip = ip_hdr(skb);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);
	
	printk(KERN_DEBUG "TCPR packet from application (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);

	read_lock(&connections_lock);
	c = lookup_internal(ip->saddr, ip->daddr, tcp->source, tcp->dest);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;
		c = connection_create(ip->saddr, ip->daddr,
				      tcp->source, tcp->dest);
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
	switch (tcpr_filter(&c->tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4)) {
	case TCPR_DELIVER:
		printk(KERN_DEBUG "Delivering packet.\n");
		verdict = NF_ACCEPT;
		break;
	case TCPR_DROP:
		printk(KERN_DEBUG "Dropping packet.\n");
		break;
	case TCPR_RESET:
		printk(KERN_DEBUG "Dropping packet and sending RST.\n");
		reset(c);
		break;
	case TCPR_RECOVER:
		printk(KERN_DEBUG "Dropping packet and sending SYN ACK.\n");
		recover(c);
		break;
	default:
		printk(KERN_DEBUG "Unknown TCPR response.\n");
		BUG();
	}
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

static unsigned int tcpr_tg_peer(struct sk_buff *skb)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	int done;

	ip = ip_hdr(skb);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	printk(KERN_DEBUG "TCPR packet from peer (syn %d, ack %d, fin %d, rst %d)\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);


	read_lock(&connections_lock);
	c = lookup_external(ip->daddr, ip->saddr, tcp->dest, tcp->source);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;
		c = connection_create(ip->daddr, ip->saddr,
				      tcp->dest, tcp->source);
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

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	if (*peer)
		return tcpr_tg_peer(skb);
	else
		return tcpr_tg_application(skb);
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
