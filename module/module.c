#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>

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

	list_for_each_entry(c, &connections, list)
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.internal_port == port)
			return c;
	return NULL;
}

static struct connection *lookup_external(uint32_t address,
					  uint32_t peer_address,
					  uint16_t port,
					  uint16_t peer_port)
{
	struct connection *c;

	list_for_each_entry(c, &connections, list)
		if (c->peer_address == peer_address
		    && c->address == address
		    && c->tcpr.saved.peer.port == peer_port
		    && c->tcpr.saved.external_port == port)
			return c;
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

	c = kmalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		write_unlock(&connections_lock);
		return NULL;
	}

	INIT_LIST_HEAD(&c->list);
	memset(&c->tcpr, 0, sizeof(c->tcpr));
	c->address = address;
	c->peer_address = peer_address;
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

static void update(struct connection *c)
{
	/* FIXME: inject update */
}

static void reset(struct connection *c)
{
	/* FIXME: inject update */
}

static void recover(struct connection *c)
{
	/* FIXME: inject update */
}

static int tcpr_open(struct inode *inode, struct file *file)
{
	printk(KERN_ERR "Opened TCPR handle.\n");
	file->private_data = NULL;
	return 0;
}

static int tcpr_release(struct inode *inode, struct file *file)
{
	struct connection *c = file->private_data;

	if (c != NULL && atomic_dec_and_test(&c->refcnt))
		connection_close(c);
	printk(KERN_ERR "Closed TCPR handle.\n");
	return 0;
}

static long tcpr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct connection *c = file->private_data;
	int ret;

	printk(KERN_ERR "Handling TCPR ioctl.\n");
	if (cmd == TCPR_ATTACH) {
		struct tcpr_connection tc;

		printk(KERN_ERR "TCPR_ATTACH.\n");

		if (c != NULL) {
			printk(KERN_ERR "Attempted to reattach TCPR handle.\n");
			return -EEXIST;
		}
		
		ret = copy_from_user(&tc, (struct tcpr_connection __user *)arg,
				     sizeof(tc));
		if (ret) {
			printk(KERN_ERR "Could not access TCPR connection information.\n");
			return ret;
		}

		c = connection_create(tc.address, tc.peer_address, tc.port, tc.peer_port);
		if (!c) {
			printk(KERN_ERR "Could not create TCPR connection.\n");
			return -ENOMEM;
		}

		printk(KERN_ERR "TCPR_ATTACH We made it?\n");

		file->private_data = c;
		atomic_inc(&c->refcnt);
		return 0;
	} else if (c == NULL) {
		printk(KERN_ERR "TCPR handle is unattached.\n");
		return -ENOENT;
	}

	printk(KERN_ERR "Handling attached TCPR ioctl.\n");

	spin_lock(&c->tcpr_lock);
	switch (cmd) {
	case TCPR_GET:
		ret = copy_to_user((struct tcpr __user *)arg,
				   &c->tcpr, sizeof(c->tcpr));
		if (ret) {
			spin_unlock(&c->tcpr_lock);
			return ret;
		}
		break;

	case TCPR_ACK:
		c->tcpr.saved.ack = htonl(ntohl(c->tcpr.saved.ack) + arg);
		update(c);
		break;
		
	case TCPR_DONE_READING:
		c->tcpr.saved.done_reading = 1;
		break;

	case TCPR_DONE_WRITING:
		c->tcpr.saved.done_writing = 1;
		break;

	case TCPR_CLOSE:
		c->tcpr.saved.done_reading = 1;
		c->tcpr.saved.done_writing = 1;
		break;

	case TCPR_KILL:
		reset(c);
		break;

	case TCPR_WAIT:
		spin_unlock(&c->tcpr_lock);
		wait_event_interruptible(c->wait, c->tcpr.done);
		return 0;

	case TCPR_DONE:
		if (!c->tcpr.done) {
			c->tcpr.done = 1;
			wake_up_interruptible(&c->wait);
			connection_close(c);
		}
		break;

	default:
		spin_unlock(&c->tcpr_lock);
		return -ENOIOCTLCMD;
	}

	spin_unlock(&c->tcpr_lock);
	return 0;
}

static unsigned int tcpr_tg(struct sk_buff *skb,
			    const struct xt_action_param *par)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	unsigned int verdict = NF_DROP;
	int done;
	
	if (!skb_make_writable(skb, skb->len))
		return verdict;

	ip = ip_hdr(skb);
	tcp = tcp_hdr(skb);

	read_lock(&connections_lock);
	c = lookup_internal(ip->saddr, ip->daddr, tcp->source, tcp->dest);
	read_unlock(&connections_lock);
	if (!c)
		return verdict;

	spin_lock(&c->tcpr_lock);
	done = c->tcpr.done;
	switch (tcpr_filter(&c->tcpr, tcp, tcp_hdrlen(skb))) {
	case TCPR_DELIVER:
		verdict = NF_ACCEPT;
		break;
	case TCPR_DROP:
		break;
	case TCPR_RESET:
		reset(c);
		break;
	case TCPR_RECOVER:
		recover(c);
		break;
	}
	if (c->tcpr.done && !done) {
		wake_up_interruptible(&c->wait);
		connection_close(c);
	}
	spin_unlock(&c->tcpr_lock);
	return verdict;
}

static unsigned int tcpr_peer_tg(struct sk_buff *skb,
				 const struct xt_action_param *par)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	int done;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	ip = ip_hdr(skb);
	tcp = tcp_hdr(skb);

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

	spin_lock(&c->tcpr_lock);
	done = c->tcpr.done;
	tcpr_filter_peer(&c->tcpr, tcp, tcp_hdrlen(skb));
	if (c->tcpr.done && !done) {
		wake_up_interruptible(&c->wait);
		connection_close(c);
	}
	spin_unlock(&c->tcpr_lock);
	return NF_ACCEPT;
}

static struct xt_target tcpr_tg_regs[] = {
	{
		.name = "tcpr",
		.family = AF_INET,
		.proto = IPPROTO_TCP,
		.target = tcpr_tg,
		.me = THIS_MODULE,
	},
	{
		.name = "tcprpeer",
		.family = AF_INET,
		.proto = IPPROTO_TCP,
		.target = tcpr_peer_tg,
		.me = THIS_MODULE,
	},
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

	ret = xt_register_targets(tcpr_tg_regs, 2);
	if (ret < 0) {
		printk(KERN_ERR "Unable to register TCPR Xtables targets\n");
		cdev_del(&tcpr_cdev);
		unregister_chrdev_region(tcpr_dev, 1);
	}

	printk(KERN_ERR "TCPR loaded with major %u and minor %u.\n", MAJOR(tcpr_dev), MINOR(tcpr_dev));
	return 0;
}

static void __exit tcpr_tg_exit(void)
{
	xt_unregister_targets(tcpr_tg_regs, 2);
	cdev_del(&tcpr_cdev);
	unregister_chrdev_region(tcpr_dev, 1);
	printk(KERN_ERR "TCPR unloaded\n");
}

module_init(tcpr_tg_init);
module_exit(tcpr_tg_exit);

MODULE_AUTHOR("Robert Surton <burgess@cs.cornell.edu>");
MODULE_DESCRIPTION("Xtables: TCPR target");
MODULE_LICENSE("BSD/GPL");
MODULE_ALIAS("ipt_tcpr");
