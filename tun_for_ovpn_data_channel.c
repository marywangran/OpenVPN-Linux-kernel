/*
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: tun.c,v 1.15 2002/03/01 02:44:24 maxk Exp $
 */

/*
 *  Changes:
 *
 *  Mike Kershaw <dragorn@kismetwireless.net> 2005/08/14
 *    Add TUNSETLINK ioctl to set the link encapsulation
 *
 *  Mark Smith <markzzzsmith@yahoo.com.au>
 *    Use random_ether_addr() for tap MAC address.
 *
 *  Harald Roelle <harald.roelle@ifi.lmu.de>  2004/04/20
 *    Fixes in packet dropping, queue length setting and queue wakeup.
 *    Increased default tx queue length.
 *    Added ethtool API.
 *    Minor cleanups
 *
 *  Daniel Podlejski <underley@underley.eu.org>
 *    Modifications for 2.3.99-pre5 kernel.
 */

/*
 * 我，又一次自私地使用了tun.c，不过这次的工作和tun本身并没有太大的关系，
 * 只是想做一个简单的OpenVPN短路hack，仅此而已，我使用tun做修改是因为简单，
 * 毕竟我只是需要将一个socket和tun联系起来，仅此而已，我需要做的就是短接
 * UDP socket和tun网卡，仅此而已....  :)
 *
 * 数据通道进入内核的好处是显而易见的，多处理操作的效率由softirq分发系统决定，
 * 而这个是简单的，在8核心处理器上，经过测试，使用Intel 82583多队列卡，按照
 * tuple做hash中断分发，保持cache活性的基础上，也能首先OpenVPN协议的高速解析，
 * 任何用户态的多线程架构与之相比都爆弱。但是此时问题浮现：
 *
 *  1.不是说内核态处理控制面而用户态处理数据面吗？对于OpenVPN，怎么反过来了啊，
 *    有点懵了！是的，数据面放到用户态只善作个幻象，现如今不是还没有很好的实例嘛...
 *    我并非说用户态多线程不好，只是对OpenVPN而言的，不信你试试。好了，在PF RING
 *    还玩不转的时候，我只能这样，也不容易。
 *  2.这里没有使用加密，接口是有了，但是没有高效的实现，我可不想OpenVPN成为Yet 
 *    Another IPSec
 * 
 * 问题多多，marywangran@126.com，还是这个邮箱
 *
 **/

#define DRV_NAME	"tun"
#define DRV_VERSION	"1.6"
#define DRV_DESCRIPTION	"Universal TUN/TAP device driver"
#define DRV_COPYRIGHT	"(C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/crc32.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/checksum.h>
#include <net/sock.h>
#include <net/udp.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/jhash.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>


#include <asm/system.h>
#include <asm/uaccess.h>

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
static int debug;

#define DBG  if(tun->debug)printk
#define DBG1 if(debug==2)printk
#else
#define DBG( a... )
#define DBG1( a... )
#endif

/* 定义一个OpenVPN封装类型 */
#define UDP_ENCAP_OVPN	20
/* 连接一个UDP套接字和TUN网卡的ioctl命令 */
#define TUNLINKOVPN   _IOW('T', 216, int)
/* 添加一个multi_instance的ioctl命令 */
#define TUNADDMILTI   _IOW('T', 217, int)
/* 为一个multi_instance添加一个虚拟地址的ioctl命令 */
#define TUNSETMIVIP   _IOW('T', 218, int)
/* 删除一个multi_instance的ioctl命令 */
#define TUNDELMILTI   _IOW('T', 219, int)
/* 设置密钥的ioctl命令 */
#define TUNSETMKEY   _IOW('T', 220, int)
/* 获取密钥的ioctl命令 */
#define TUNGETMKEY   _IOW('T', 221, int)

#define OVPN_OPT_DEC    0
#define OVPN_OPT_ENC    1

void hexdump(char *desc, unsigned char *buf, int len)
{
    if (debug == 0) {
        return;
    }
    printk("\n##########DESC:%s\n", desc);
    while(len--) {
        printk("%02x",*buf++);
    }
    printk("\n####### END #######\n");
}


/*
 * 用于封装ioctl命令，但不经常，也不绝对... 
 **/
struct sockfd {
	int fd;
};

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

struct tun_file {
	atomic_t count;
	struct tun_struct *tun;
	struct net *net;
};

struct tun_sock;


/* UDP的encap返回正常路径 */
#define UDP_DECAP_PASS		1
/* UDP的encap自己消费了数据包 */
#define UDP_DECAP_STOLEN	0
/* 以上的规范详细情况自行看UDP处理以及IPSec/L2TP作为一个例子的实现 */

/*
 * OpenVPN的常量定义，我是不是该准备一个头文件和C文件呢？
 * 借用tun.c总不是什么长久之事！tun又不是只用于OpenVPN啊，
 * 然而tun.c确实该加一个HOOK机制了... 
 **/
#define MAX_HASH_BUCKETS	256
/* 暂时先这么多 */
#define MAX_KEY_LENGTH      512
#define P_DATA_V1                      6
#define P_OPCODE_SHIFT                 3

/* 这个锁的粒度有点粗 */
DEFINE_SPINLOCK(ovpn_lock);

typedef u32 packet_id_type;
typedef u32 net_time_t ;

/*
 * 使用IP地址/端口对建立multi_instance 
 **/
struct instance_req {
    u32 real_addr;
    __be16 port;
};

/*
 * 为一个multi_instance添加一个虚拟IP地址，此结构体目前仅适用于
 * TUN模式。因为对于TAP模式需要实现一个列表，基于该列表实现一个
 * 虚拟交换机，哦，是的，虚拟交换机...
 * */
struct instance_vreq {
    u32 real_addr;
    u32 vaddr;
    __be16 port;
};

/* 用于向内核传递密钥或者反过来传递密钥 */
/* 是不是应该用PF_KEY啊，小小说不能，我就不用了 */
struct key_block {
    struct instance_req ir;
    unsigned char key1[MAX_KEY_LENGTH];
    unsigned char key2[MAX_KEY_LENGTH];
    unsigned char key3[MAX_KEY_LENGTH];
    unsigned char key4[MAX_KEY_LENGTH];
};

/*
 * 用于实现OpenVPN的防重放机制 
 **/
struct packet_id_send
{
	packet_id_type id;
	time_t time;
};

/*
 * 用于实现OpenVPN的防重放机制，但是天啊...里面的字段在协议移植阶段
 * 是没有任何用武之地的，是的，没有用...
 * */
struct packet_id_rec
{
	time_t last_reap;           /* last call of packet_id_reap */
	time_t time;                /* highest time stamp received */
	packet_id_type id;          /* highest sequence number received */
	int seq_backtrack;          /* set from --replay-window */
	int time_backtrack;         /* set from --replay-window */
	int max_backtrack_stat;     /* maximum backtrack seen so far */
	int initialized;           /* true if packet_id_init was called */
	struct seq_list *seq_list;  /* packet-id "memory" */
	const char *name;
	int unit;
};

/*
 * 用于实现OpenVPN的防重放机制，目前的版本仅仅是为了例行公事，发送前
 * 在OpenVPN头中封装一个递增的packet ID，但是注意，不支持LONG FORM！！
 * */
struct packet_id
{
	struct packet_id_send send;
	struct packet_id_rec rec;
};

/*
 * 万恶又万能的multi_instance，是不是有点熟悉呢？？对！This is it!
 * */
struct multi_instance {
	struct list_head list;
	struct hlist_node rhnode;
	struct hlist_node vhnode;
	struct sock *sk;
	struct packet_id packet_id;
    struct key_block mikb;
	u32 saddr;
	u32 daddr;
	unsigned char hsaddr[ETH_ALEN];
	/* for a learning Vswitch , it is a list! TODO */
	unsigned char hdaddr[ETH_ALEN];
	u32 real_saddr;
	u32 real_daddr;
	__be16 dport;
    void (*mi_destroy)(struct multi_instance *);
};

/*
 * 我的本意并不是移植OpenVPN，而是实现一个新的协议，but，but，but，but
 * 苦于没有客户端，我为何不使用现成的OpenVPN呢？？它的协议足够简单啊足够简单！
 * */
#define CIPHER_NAME_LENGTH  32
struct encap_context {
	struct hlist_head hash[MAX_HASH_BUCKETS];
	struct hlist_head vhash[MAX_HASH_BUCKETS];
    /* 最终还是说服了自己，解除了OpenVPN和tun之间的耦合 :) */
	int (*encap_xmit)(struct tun_struct *tun, struct sk_buff *skb);
    /* 我并没有区分cipher和auth，也就是说，我把加密运算和HMAC统一使用一套回调函数完成 :>| */
    /* 暂时，我使用了Linux内核的tfm框架 */
    struct crypto_cipher *tfm;
    char cipher_name[CIPHER_NAME_LENGTH];
	int (*cipher_init)(void *);
    int (*cipher_pre_enc)(struct encap_context *, struct sk_buff *, int, struct multi_instance *);
    int (*cipher_setkey)(struct multi_instance *, struct crypto_cipher *, const u8 *, unsigned int);
	struct sk_buff * (*cipher_enc)(struct encap_context *, struct sk_buff *, int, void *);
	int (*cipher_fini)(void *);
};

/*
 * 就是它！这就是OpenVPN协议的本质！瞧瞧看吧，你仅仅需要设置3个字段足矣！
 * ocode:这个字段其实包含以下两个部分
 *      opt     :很显然，我在内核中只处理数据通道，那么它是P_DATA_V1常量
 *      key_id  :这个keyid用于切换密钥。目前使用定值0，即版本0.1不支持密钥重协商，
 *              然则这只是个开始...
 * id: 此字段用于封装将要发送的数据包的ID，防重放攻击
 * 可见，关键的关键就是如何填充以下结构体的问题...对了，我可以说填充UDP头和IP头不是个事儿
 * 吗？如果它们都成了事儿，还怎么好意思说自己比较喜欢折腾内核协议栈呢... :(
 **/
struct ovpnhdr {
	u8 ocode;
	packet_id_type id;
    /* 注意，不要按照最长字段自然对齐，这是在玩网络，而不是内存！ */	
} __attribute__((packed));

struct tun_struct {
	struct tun_file		*tfile;
	unsigned int 		flags;
	uid_t			owner;
	gid_t			group;

	struct net_device	*dev;
	struct fasync_struct	*fasync;

	struct tap_filter       txflt;
	struct socket		socket;
	struct sock		*encap_sock;
	/* pass THIS into encap_xmit like OO ?? */
    /* 对于这个回调函数，我该说些什么呢？实际上，我真的该将其放在encap_context里面 */
	/* int (*encap_xmit)(struct tun_struct *tun, struct sk_buff *skb);*/
	struct encap_context ctx;

#ifdef TUN_DEBUG
	int debug;
#endif
};

struct tun_sock {
	struct sock		sk;
	struct tun_struct	*tun;
};

/*
 * 这个destroy函数用于清理一个multi_instance，一个析构 
 **/
void ovpn_destroy(struct multi_instance *mi)
{
    return;
}

/*
 * 根据一个IP地址和端口删除一个multi_instance
 **/
static void ovpn_del_real_instance(	struct tun_struct *tun, 
					u32 real_addr,
					__be16 port)
{
	struct multi_instance *tmi;
	struct multi_instance *mi;
	struct hlist_node *node;
	unsigned int hash = jhash_2words(real_addr, port, 0);

	spin_lock_bh(&ovpn_lock);
	hlist_for_each_entry(tmi, node, &tun->ctx.hash[hash % MAX_HASH_BUCKETS], rhnode) {
		if (real_addr == tmi->real_daddr &&
			port == tmi->dport) {
			mi = tmi;
		}
	}
	if (!mi) {
		spin_unlock_bh(&ovpn_lock);
		return ;
	}
	hlist_del(&mi->rhnode);
	hlist_del(&mi->vhnode);
	spin_unlock_bh(&ovpn_lock);
	kfree(mi);
}

/*
 * 添加一个multi_instance
 **/
static struct multi_instance *ovpn_add_real_instance(	struct tun_struct *tun, 
					u32 real_addr,
					__be16 port)
{
	struct multi_instance *ret = NULL;
	struct multi_instance *tmi;
	struct hlist_node *node;
	unsigned int hash = jhash_2words(real_addr, port, 0);

	spin_lock_bh(&ovpn_lock);
	hlist_for_each_entry(tmi, node, &tun->ctx.hash[hash % MAX_HASH_BUCKETS], rhnode) {
		if (real_addr == tmi->real_daddr &&
			port == tmi->dport) {
			spin_unlock_bh(&ovpn_lock);
			return tmi;
		}
	}
	ret = kzalloc(sizeof(struct multi_instance), GFP_ATOMIC);
	if (!ret) {
		spin_unlock_bh(&ovpn_lock);
		return NULL;
	}
	ret->dport = port;	
	ret->real_daddr = real_addr;
	ret->sk = tun->encap_sock;
	ret->mi_destroy = ovpn_destroy;
	ret->real_saddr = inet_sk(ret->sk)->saddr;
	hash = jhash_2words(ret->real_daddr, ret->dport, 0);
    INIT_HLIST_NODE(&ret->rhnode);
    INIT_HLIST_NODE(&ret->vhnode);
	hlist_add_head(&ret->rhnode, &tun->ctx.hash[hash % MAX_HASH_BUCKETS]);
	spin_unlock_bh(&ovpn_lock);
    /* setkey 应该在专门的ioctl 中 */
    tun->ctx.cipher_setkey(ret, tun->ctx.tfm, NULL, 0);
	return ret;
}

/*
 * 为一个multi_instance添加一个虚拟IP地址，这个本来应该实现成一个虚拟交换机的
 * BUT对于TUN模式而言，我采用了替换模式，也就是说，我的这个版本并不支持iroute
 * 不支持又怎么样呢？早晚的事吧。希望，真心希望James Yonan不要打我哦。。。
 **/
static int ovpn_add_virtual_instance(	struct tun_struct *tun, 
					u32 real_addr,
					__be16 port,
					u32 addr)
{
	struct multi_instance *mi;
	struct multi_instance *tmi;
	struct hlist_node *node;
	unsigned int hash = jhash_2words(real_addr, port, 0);

	spin_lock_bh(&ovpn_lock);
	hlist_for_each_entry(tmi, node, &tun->ctx.hash[hash % MAX_HASH_BUCKETS], rhnode) {
		if (real_addr == tmi->real_daddr &&
			port == tmi->dport) {
			mi = tmi;
			break;
		}
	}
	if (!mi) {
		spin_unlock_bh(&ovpn_lock);
		return -1;
	}
	hlist_del_init(&mi->vhnode);
	mi->daddr = addr;
	hash = jhash_1word(mi->daddr, 0);
	hlist_add_head(&mi->vhnode, &tun->ctx.vhash[hash % MAX_HASH_BUCKETS]);
	spin_unlock_bh(&ovpn_lock);
	return 0;
}

struct ovpnhdr *ovpn_hdr(struct sk_buff *skb)
{
	return (struct ovpnhdr*)(skb->data);
}

static struct sk_buff *ovpn_pre_endecrypt(int mode, 
                            struct tun_struct *tun, 
                            struct sk_buff *skb,
                            struct multi_instance *mi)
{
	u8 *data;
	u8 ocode = 0;
    struct sk_buff *sk_ret = NULL;
	int op;
    if (mode == OVPN_OPT_DEC) {
	    data = skb->data;
	    ocode = data[0];
	    op = ocode >> P_OPCODE_SHIFT;
	    if (op != P_DATA_V1) {
            sk_ret = NULL;
		    goto out;		
	    }
        sk_ret = skb;
    } else if (mode == OVPN_OPT_ENC){
        /* 我在这里添加padding以及设置packet id */
        /* 早先在仅仅移植协议的时候，我将设置packet id
         * 放在了post里面，由于packet id也是要加密的，所以必须放在
         * pre里面 
         **/
        struct ovpnhdr *ohdr;
	    ohdr = ovpn_hdr(skb);
	    ++mi->packet_id.send.id;
	    ohdr->id = htonl(mi->packet_id.send.id);
	    ohdr->ocode = (P_DATA_V1 << P_OPCODE_SHIFT) | 0x0;
        if (tun->ctx.cipher_pre_enc(&tun->ctx, skb, mode, mi)){
            sk_ret = NULL;
            goto out;
        }
        sk_ret = skb;
    } else {
        sk_ret = NULL;
        goto out;
    }
out:
    return sk_ret;
}

static struct sk_buff * ovpn_endecrypt(int mode, 
                            struct tun_struct *tun, 
                            struct sk_buff *skb,
                            struct multi_instance *mi)
{
    
    /* return tun->ctx.endecrypt(tun, skb); */
    tun->ctx.cipher_enc(&tun->ctx, skb, mode, NULL);
    return skb;
}

static struct sk_buff  *ovpn_post_endecrypt(int mode, 
                                struct tun_struct *tun, 
                                struct sk_buff *skb,
                                struct multi_instance *mi)
{
    struct sk_buff *sk_ret = NULL;
    if (mode == OVPN_OPT_ENC) {
	    //skb_pull(skb, sizeof(struct ovpnhdr) - 1);
        sk_ret = skb;
    } else if (mode == OVPN_OPT_DEC) {
        sk_ret = skb;
    } else {
        sk_ret = NULL;
        goto out;
    }
out:
    return sk_ret;
}

/*
 * 真正的亡灵序曲在这里大肆打折！
 * 它截取了UDP的receive处理流程，它可以自行处理数据包，也可以将数据包返回给正常的UDP receive流程
 * 点赞的说，它就是一个UDP Netfilter，或者叫做UDPFilter更好！它也有自己的规范：
 *
         * This is an encapsulation socket so pass the skb to
         * the socket's udp_encap_rcv() hook. Otherwise, just
         * fall through and pass this up the UDP socket.
         * up->encap_rcv() returns the following value:
         * =0 if skb was successfully passed to the encap
         *      handler or was discarded by it.
         * >0 if skb should be passed on to UDP.
         * <0 if skb should be resubmitted as proto -N
         * 
 * 有点蹩脚，但是毕竟是一种HOOK机制，实用主义者会说，就是它了！                                                             
 */
static int ovpn_data_channel_decap_recv(struct sock *sk, struct sk_buff *skb)
{
    struct sk_buff *skb2 = NULL;
	struct tun_struct *tun = NULL;
    struct multi_instance *mi = NULL;
	struct multi_instance *tmi;
    struct hlist_node *node;
	struct iphdr *hdr = ip_hdr(skb);
	struct udphdr *ud = udp_hdr(skb);
	int ret = UDP_DECAP_PASS;
	u32 addr = hdr->saddr;
    __be16 port = ud->source;
	unsigned int hash = jhash_2words(addr, port, 0);

	tun = (struct tun_struct *)sk->sk_user_data;
	

    spin_lock_bh(&ovpn_lock);
	hlist_for_each_entry(tmi, node, &tun->ctx.hash[hash % MAX_HASH_BUCKETS], rhnode) {
		if (addr == tmi->real_daddr &&
                port == tmi->dport) {
			mi = tmi;
			break;
		}
	}
	spin_unlock_bh(&ovpn_lock);
    if (!mi) {
        goto out;
    }

	skb_pull(skb, sizeof(struct udphdr));
	
    /* decrypt 
     * 很显然，这是关键！数据解密！
     * 但是谁能告诉我内核中怎么高效使用加解密，如果不能高效，
     * 那么起码保证灵活，就像OpenSSL那样！进入了内核态，我突然
     * 突然想到了OpenSSL的好，人，不能忘本啊  :<
     */

    /* 首先，判断是否是数据通道，进行例行检查，获取必要的密钥套件 */
    if ((skb2 = ovpn_pre_endecrypt(OVPN_OPT_DEC, tun, skb, mi)) == NULL) {
	    skb_push(skb, sizeof(struct udphdr));
        goto out;
    }
    skb = skb2;
	
    /* 实际的解密操作，注意在内部可能要进行skb的realloc操作 */
    if ((skb2 = ovpn_endecrypt(OVPN_OPT_DEC, tun, skb, mi)) == NULL) {
	    skb_push(skb, sizeof(struct udphdr));
        goto out;
    }
    skb = skb2;

    /* 参考OpenVPN的post decrypt操作 */
    if ((skb2 = ovpn_post_endecrypt(OVPN_OPT_DEC, tun, skb, mi)) == NULL) {
	    skb_push(skb, sizeof(struct udphdr));
        goto out;
    }
    skb = skb2;

    /* 解密完成，推进一个OpenVPN头的长度 */
	skb_pull(skb, sizeof(struct ovpnhdr));
	switch (tun->flags & TUN_TYPE_MASK) {
		case TUN_TUN_DEV:
            switch (skb->data[0] & 0xf0) {
                /* 当前只支持IPv4 */
                case 0x40:
                    break;
                default:
	                skb_push(skb, sizeof(struct ovpnhdr));
	                skb_push(skb, sizeof(struct udphdr));
				    goto out;
                    
			}
			skb_reset_mac_header(skb);
            /* 是时候丢掉西装外衣了，口袋里的通行证会将你引入深渊，
             * 不信的话，注释此言，在OpenVPN客户端机器上ping一下
             * 服务端的虚拟IP试一试 
             **/
            skb_dst_drop(skb);
			skb->protocol = htons(ETH_P_IP);;
	        skb->dev = tun->dev;
			ret = UDP_DECAP_STOLEN;
			break;
		case TUN_TAP_DEV:
			// TODO
			goto out;
			break;
	}
    /* 模拟TUN虚拟网卡接收，此时截获处理正式完成，
     * 告诉UDP，嗨，你的数据我已经帮你处理了 
     **/
	netif_rx_ni(skb);
    
out:
	return ret;
}

/*
 * 封装UDP
 * 本来想直接调用socket的sendto/sendmsg的，然而太过恶心与繁琐，加之需要skb和msg之间的拷贝
 * 为了省事而影响效率这样不值！还是自己封装吧，反正也不难
 **/
static int encap_udp(struct sk_buff *skb, struct multi_instance *mi, unsigned int *pdlen)
{
	struct udphdr *uh;
	struct inet_sock *inet = inet_sk(mi->sk);
	int len = *pdlen + sizeof(struct udphdr);
	
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	
	uh = udp_hdr(skb);
	uh->source = htons(inet->num);
	uh->dest = mi->dport;
	uh->len = htons(len);
	uh->check = 0;
	
    /* 注意这里有优化空间，ufo是否启用，硬件是否能帮我计算checksum呢？？ */
    uh->check = 0;
	uh->check = csum_tcpudp_magic(mi->real_saddr, mi->real_daddr, len,
				      mi->sk->sk_protocol, csum_partial(uh,
                                                        len, 
                                                        0));
	
	return 0;	
}

/* 
 * IP层的封装与发送函数，注意，这里很不方便使用ip_queue_xmit 
 **/
static int encap_ip_xmit(struct sk_buff *skb, struct multi_instance *mi, struct iphdr *old)
{
	struct iphdr *iph;
	struct dst_entry *dst;

	skb_push(skb, sizeof(struct iphdr));
    /* 如影随形 */
	skb_reset_network_header(skb);
	
	iph = ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr)>>2;
	iph->frag_off		=	0;//old->frag_off;
	iph->protocol		=	IPPROTO_UDP;
	iph->tos		=	old->tos;
	iph->daddr		=	mi->real_daddr;
	iph->saddr		=	mi->real_saddr;
	iph->ttl		=	old->ttl;
    /* 这个reroute频繁用于OUTPUT Netfilter HOOK，但问Rusty本人，
     * Netfilter的OUTPUT设计为何如何之好 */
	if (ip_route_me_harder(skb, RTN_LOCAL)!= 0) {
		return -1;
	}
	dst = skb_dst(skb);	

	ip_select_ident(iph, dst, NULL);
	return ip_local_out(skb);
}


static struct sk_buff *encap_ovpn(struct sk_buff *skb, struct multi_instance *mi, int *pdlen)
{
    struct sk_buff *skb2 = NULL;
    struct tun_struct *tun;

	
    if (!mi) {
        goto out;
    }

    tun = mi->sk->sk_user_data;
    if (!tun) {
        goto out;
    }

    /* encrypt 
     * 很显然，这是关键！数据解密！
     * 但是谁能告诉我内核中怎么高效使用加解密，如果不能高效，
     * 那么起码保证灵活，就像OpenSSL那样！进入了内核态，我突然
     * 突然想到了OpenSSL的好，人，不能忘本啊  :<
     */

    /* 如影随形 */
	skb_push(skb, sizeof(struct ovpnhdr));
    *pdlen += sizeof(struct ovpnhdr);

    /* 首先，判断是否是数据通道，进行例行检查，获取必要的密钥套件 */
    if ((skb2 = ovpn_pre_endecrypt(OVPN_OPT_ENC, tun, skb, mi)) == NULL) {
        skb = NULL;
        goto out;
    }
    skb = skb2;
    *pdlen = skb->len;
	
    /* 实际的解密操作，注意在内部可能要进行skb的realloc操作 */
    if ((skb2 = ovpn_endecrypt(OVPN_OPT_ENC, tun, skb, mi)) == NULL) {
        skb = NULL;
        goto out;
    }
    skb = skb2;
    *pdlen = skb->len;

    /* 参考OpenVPN的post decrypt操作 */
    if ((skb2 = ovpn_post_endecrypt(OVPN_OPT_ENC, tun, skb, mi)) == NULL) {
        skb = NULL;
        goto out;
    }
    skb = skb2;
    *pdlen = skb->len;

out:
	return skb;	
}

/*
 * hard_xmit中的封装函数，用于短路处理
 **/
static int ovpn_data_channel_encap_xmit(struct tun_struct *tun, struct sk_buff *skb)
{
	unsigned int max_headroom;
    int ret = 0;
	struct sock *sk;
    struct sk_buff *skb2 = NULL;
	struct multi_instance *mi = NULL;
	struct hlist_node *node;
	struct iphdr *old_iphdr = NULL;
    unsigned int dlen = skb->len;

	sk = tun->encap_sock;
	if (!sk) {
        ret = -1;
		goto out;
	}
	if (sk->sk_protocol != IPPROTO_UDP) {
        ret = -1;
		goto out;
	}
	
    /* 足够了吧！连诸多加密算法携带的padding都TMD够了！够了够了！想起了在哈尔滨的时候，
     * 因为我让全班的人熬到7点才吃晚饭...只因为我在老师下课的时候说了句：够了！
     **/
#define I_THINK_THIS_LENGTH_ENOUGH_BECAUSE_OF_XXX  64    
	max_headroom = (I_THINK_THIS_LENGTH_ENOUGH_BECAUSE_OF_XXX + 
                    LL_RESERVED_SPACE(tun->dev)         + 
				    sizeof(struct iphdr)                +
				    sizeof(struct udphdr)               +
				    sizeof(struct ovpnhdr));

	switch (tun->flags & TUN_TYPE_MASK){
	case TUN_TUN_DEV:
	{
		struct iphdr *hdr = ip_hdr(skb);
		u32 addr = hdr->daddr;
		struct multi_instance *tmi;
		unsigned int hash = jhash_1word(addr, 0);

		old_iphdr = hdr;
		spin_lock_bh(&ovpn_lock);
		hlist_for_each_entry(tmi, node, &tun->ctx.vhash[hash % MAX_HASH_BUCKETS], vhnode) {
			if (addr == tmi->daddr) {
				mi = tmi;
				break;
			}
		}
		spin_unlock_bh(&ovpn_lock);
	}
		break;
	case TUN_TAP_DEV:
	{
		// TODO
        ret = -1;
		
	}
		break;

	}	
	if (!mi) {
        ret = -1;
		goto out;
	}
	if (skb_headroom(skb) < max_headroom || !skb_clone_writable(skb, 0)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
            ret = -1;
			goto out;
		}
        skb_dst_set(new_skb, skb_dst(skb));

		dev_kfree_skb(skb);
		skb = new_skb;
	}

	if ((skb2 = encap_ovpn(skb, mi, &dlen)) == NULL) {
        ret = 1;
        dev_kfree_skb(skb);
        goto out;
    }
    skb = skb2;
	
	if (encap_udp(skb, mi, &dlen)) {
        dev_kfree_skb(skb);
        ret = 1;
        goto out;
    }
	/* GO AWAY?? 注意返回值转换 */
	ret = encap_ip_xmit(skb, mi, old_iphdr);
    if (ret < 0) {
        ret = 1;
    }
out:
	return ret;
}

static inline struct tun_sock *tun_sk(struct sock *sk)
{
	return container_of(sk, struct tun_sock, sk);
}

static int tun_attach(struct tun_struct *tun, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	int err;

	ASSERT_RTNL();

	netif_tx_lock_bh(tun->dev);

	err = -EINVAL;
	if (tfile->tun)
		goto out;

	err = -EBUSY;
	if (tun->tfile)
		goto out;

	err = 0;
	tfile->tun = tun;
	tun->tfile = tfile;
	dev_hold(tun->dev);
	sock_hold(tun->socket.sk);
	atomic_inc(&tfile->count);

out:
	netif_tx_unlock_bh(tun->dev);
	return err;
}

static void __tun_detach(struct tun_struct *tun)
{
    struct sock *sk;
	/* Detach from net device */
	netif_tx_lock_bh(tun->dev);
    /**/
    sk = tun->encap_sock;
    if (sk) {
        int i;
		/* 重置操作 */
		(udp_sk(sk))->encap_type = 0;
		(udp_sk(sk))->encap_rcv = NULL;
		sk->sk_user_data = NULL;	
		tun->encap_sock = NULL;
		tun->ctx.encap_xmit = NULL;
        for (i = 0; i < MAX_HASH_BUCKETS; i++) {
            struct multi_instance *mi;
            struct hlist_head *head;
            struct hlist_node *node, *tmp;
            head = &tun->ctx.hash[i];
            hlist_for_each_entry_safe(mi, node, tmp, head, rhnode) {
                hlist_del(node);
	            hlist_del(&mi->vhnode);
                if (mi->mi_destroy) {
                    mi->mi_destroy(mi/* THIS ? self ? Okey,thinking in JAVA */);
                }
                kfree(mi);
            }
        }
        /* 这里才减少引用计数！因为你并不晓得且不能假设tun和socket的关闭顺序 */
        if (sk) {
            sockfd_put(sk->sk_socket);
        }
    }
	tun->tfile = NULL;
	netif_tx_unlock_bh(tun->dev);

	/* Drop read queue */
	skb_queue_purge(&tun->socket.sk->sk_receive_queue);

	/* Drop the extra count on the net device */
	dev_put(tun->dev);
}

static void tun_detach(struct tun_struct *tun)
{
	rtnl_lock();
	__tun_detach(tun);
	rtnl_unlock();
}

static struct tun_struct *__tun_get(struct tun_file *tfile)
{
	struct tun_struct *tun = NULL;

	if (atomic_inc_not_zero(&tfile->count))
		tun = tfile->tun;

	return tun;
}

static struct tun_struct *tun_get(struct file *file)
{
	return __tun_get(file->private_data);
}

static void tun_put(struct tun_struct *tun)
{
	struct tun_file *tfile = tun->tfile;

	if (atomic_dec_and_test(&tfile->count))
		tun_detach(tfile->tun);
}

/* TAP filterting */
static void addr_hash_set(u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	mask[n >> 5] |= (1 << (n & 31));
}

static unsigned int addr_hash_test(const u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	return mask[n >> 5] & (1 << (n & 31));
}

static int update_filter(struct tap_filter *filter, void __user *arg)
{
	struct { u8 u[ETH_ALEN]; } *addr;
	struct tun_filter uf;
	int err, alen, n, nexact;

	if (copy_from_user(&uf, arg, sizeof(uf)))
		return -EFAULT;

	if (!uf.count) {
		/* Disabled */
		filter->count = 0;
		return 0;
	}

	alen = ETH_ALEN * uf.count;
	addr = kmalloc(alen, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	if (copy_from_user(addr, arg + sizeof(uf), alen)) {
		err = -EFAULT;
		goto done;
	}

	/* The filter is updated without holding any locks. Which is
	 * perfectly safe. We disable it first and in the worst
	 * case we'll accept a few undesired packets. */
	filter->count = 0;
	wmb();

	/* Use first set of addresses as an exact filter */
	for (n = 0; n < uf.count && n < FLT_EXACT_COUNT; n++)
		memcpy(filter->addr[n], addr[n].u, ETH_ALEN);

	nexact = n;

	/* Remaining multicast addresses are hashed,
	 * unicast will leave the filter disabled. */
	memset(filter->mask, 0, sizeof(filter->mask));
	for (; n < uf.count; n++) {
		if (!is_multicast_ether_addr(addr[n].u)) {
			err = 0; /* no filter */
			goto done;
		}
		addr_hash_set(filter->mask, addr[n].u);
	}

	/* For ALLMULTI just set the mask to all ones.
	 * This overrides the mask populated above. */
	if ((uf.flags & TUN_FLT_ALLMULTI))
		memset(filter->mask, ~0, sizeof(filter->mask));

	/* Now enable the filter */
	wmb();
	filter->count = nexact;

	/* Return the number of exact filters */
	err = nexact;

done:
	kfree(addr);
	return err;
}

/* Returns: 0 - drop, !=0 - accept */
static int run_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	/* Cannot use eth_hdr(skb) here because skb_mac_hdr() is incorrect
	 * at this point. */
	struct ethhdr *eh = (struct ethhdr *) skb->data;
	int i;

	/* Exact match */
	for (i = 0; i < filter->count; i++)
		if (!compare_ether_addr(eh->h_dest, filter->addr[i]))
			return 1;

	/* Inexact match (multicast only) */
	if (is_multicast_ether_addr(eh->h_dest))
		return addr_hash_test(filter->mask, eh->h_dest);

	return 0;
}

/*
 * Checks whether the packet is accepted or not.
 * Returns: 0 - drop, !=0 - accept
 */
static int check_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	if (!filter->count)
		return 1;

	return run_filter(filter, skb);
}

/* Network device part of the driver */

static const struct ethtool_ops tun_ethtool_ops;

/* Net device detach from fd. */
static void tun_net_uninit(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_file *tfile = tun->tfile;

	/* Inform the methods they need to stop using the dev.
	 */
	if (tfile) {
		wake_up_all(&tun->socket.wait);
		if (atomic_dec_and_test(&tfile->count))
			__tun_detach(tun);
	}
}

static void tun_free_netdev(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	sock_put(tun->socket.sk);
}

/* Net device open. */
static int tun_net_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

/* Net device close. */
static int tun_net_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/* Net device start xmit */
static netdev_tx_t tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	DBG(KERN_INFO "%s: tun_net_xmit %d\n", tun->dev->name, skb->len);

	/* Drop packet if interface is not attached */
	if (!tun->tfile)
		goto drop;

	/* Drop if the filter does not like it.
	 * This is a noop if the filter is disabled.
	 * Filter can be enabled only for the TAP devices. */
	if (!check_filter(&tun->txflt, skb))
		goto drop;

	/* ?? */
	if (tun->ctx.encap_xmit) {
        
		int ret = tun->ctx.encap_xmit(tun/*this就是那个叫做JAVA编程思想的！GEB之大成*/, skb);
        /* Is this Okay？I don't known */
        /* Refer to the return value of UDP encap_rcv callback!*/
		if (ret == 0) {
			/* encap_xmit drop skb*/
			goto out;
		} else if (ret > 0) {
            goto out;
        }
		/* fall through */
	}

	if (skb_queue_len(&tun->socket.sk->sk_receive_queue) >= dev->tx_queue_len) {
		if (!(tun->flags & TUN_ONE_QUEUE)) {
			/* Normal queueing mode. */
			/* Packet scheduler handles dropping of further packets. */
			netif_stop_queue(dev);

			/* We won't see all dropped packets individually, so overrun
			 * error is more appropriate. */
			dev->stats.tx_fifo_errors++;
		} else {
			/* Single queue mode.
			 * Driver handles dropping of all packets itself. */
			goto drop;
		}
	}

	/* Enqueue packet */
	skb_queue_tail(&tun->socket.sk->sk_receive_queue, skb);
	dev->trans_start = jiffies;

	/* Notify and wake up reader process */
	if (tun->flags & TUN_FASYNC)
		kill_fasync(&tun->fasync, SIGIO, POLL_IN);
	wake_up_interruptible(&tun->socket.wait);
	return NETDEV_TX_OK;

drop:
	dev->stats.tx_dropped++;
	kfree_skb(skb);
out:
	return NETDEV_TX_OK;
}

static void tun_net_mclist(struct net_device *dev)
{
	/*
	 * This callback is supposed to deal with mc filter in
	 * _rx_ path and has nothing to do with the _tx_ path.
	 * In rx path we always accept everything userspace gives us.
	 */
	return;
}

#define MIN_MTU 68
#define MAX_MTU 65535

static int
tun_net_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < MIN_MTU || new_mtu + dev->hard_header_len > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops tun_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu		= tun_net_change_mtu,
};

static const struct net_device_ops tap_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu		= tun_net_change_mtu,
	.ndo_set_multicast_list	= tun_net_mclist,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

/* Initialize net device. */
static void tun_net_init(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		dev->netdev_ops = &tun_netdev_ops;

		/* Point-to-Point TUN Device */
		dev->hard_header_len = 0;
		dev->addr_len = 0;
		dev->mtu = 1500;

		/* Zero header length */
		dev->type = ARPHRD_NONE;
		dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;

	case TUN_TAP_DEV:
		dev->netdev_ops = &tap_netdev_ops;
		/* Ethernet TAP Device */
		ether_setup(dev);

		random_ether_addr(dev->dev_addr);

		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;
	}
    dev->priv_flags     &= ~IFF_XMIT_DST_RELEASE;
}

/* Character device part */

/* Poll */
static unsigned int tun_chr_poll(struct file *file, poll_table * wait)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	struct sock *sk;
	unsigned int mask = 0;

	if (!tun)
		return POLLERR;

	sk = tun->socket.sk;

	DBG(KERN_INFO "%s: tun_chr_poll\n", tun->dev->name);

	poll_wait(file, &tun->socket.wait, wait);

	if (!skb_queue_empty(&sk->sk_receive_queue))
		mask |= POLLIN | POLLRDNORM;

	if (sock_writeable(sk) ||
	    (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
	     sock_writeable(sk)))
		mask |= POLLOUT | POLLWRNORM;

	if (tun->dev->reg_state != NETREG_REGISTERED)
		mask = POLLERR;

	tun_put(tun);
	return mask;
}

/* prepad is the amount to reserve at front.  len is length after that.
 * linear is a hint as to how much to copy (usually headers). */
static inline struct sk_buff *tun_alloc_skb(struct tun_struct *tun,
					    size_t prepad, size_t len,
					    size_t linear, int noblock)
{
	struct sock *sk = tun->socket.sk;
	struct sk_buff *skb;
	int err;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, noblock,
				   &err);
	if (!skb)
		return ERR_PTR(err);

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;
}

/* Get packet from user space buffer */
static __inline__ ssize_t tun_get_user(struct tun_struct *tun,
				       const struct iovec *iv, size_t count,
				       int noblock)
{
	struct tun_pi pi = { 0, cpu_to_be16(ETH_P_IP) };
	struct sk_buff *skb;
	size_t len = count, align = 0;
	struct virtio_net_hdr gso = { 0 };
	int offset = 0;

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) > count)
			return -EINVAL;

		if (memcpy_fromiovecend((void *)&pi, iv, 0, sizeof(pi)))
			return -EFAULT;
		offset += sizeof(pi);
	}

	if (tun->flags & TUN_VNET_HDR) {
		if ((len -= sizeof(gso)) > count)
			return -EINVAL;

		if (memcpy_fromiovecend((void *)&gso, iv, offset, sizeof(gso)))
			return -EFAULT;

		if ((gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    gso.csum_start + gso.csum_offset + 2 > gso.hdr_len)
			gso.hdr_len = gso.csum_start + gso.csum_offset + 2;

		if (gso.hdr_len > len)
			return -EINVAL;
		offset += sizeof(gso);
	}

	if ((tun->flags & TUN_TYPE_MASK) == TUN_TAP_DEV) {
		align = NET_IP_ALIGN;
		if (unlikely(len < ETH_HLEN ||
			     (gso.hdr_len && gso.hdr_len < ETH_HLEN)))
			return -EINVAL;
	}

	skb = tun_alloc_skb(tun, align, len, gso.hdr_len, noblock);
	if (IS_ERR(skb)) {
		if (PTR_ERR(skb) != -EAGAIN)
			tun->dev->stats.rx_dropped++;
		return PTR_ERR(skb);
	}

	if (skb_copy_datagram_from_iovec(skb, 0, iv, offset, len)) {
		tun->dev->stats.rx_dropped++;
		kfree_skb(skb);
		return -EFAULT;
	}

	if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		if (!skb_partial_csum_set(skb, gso.csum_start,
					  gso.csum_offset)) {
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}
	} else if (tun->flags & TUN_NOCHECKSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		if (tun->flags & TUN_NO_PI) {
			switch (skb->data[0] & 0xf0) {
			case 0x40:
				pi.proto = htons(ETH_P_IP);
				break;
			case 0x60:
				pi.proto = htons(ETH_P_IPV6);
				break;
			default:
				tun->dev->stats.rx_dropped++;
				kfree_skb(skb);
				return -EINVAL;
			}
		}

		skb_reset_mac_header(skb);
		skb->protocol = pi.proto;
		skb->dev = tun->dev;
		break;
	case TUN_TAP_DEV:
		skb->protocol = eth_type_trans(skb, tun->dev);
		break;
	};

	if (gso.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		pr_debug("GSO!\n");
		switch (gso.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
			break;
		case VIRTIO_NET_HDR_GSO_UDP:
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
			break;
		default:
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		if (gso.gso_type & VIRTIO_NET_HDR_GSO_ECN)
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

		skb_shinfo(skb)->gso_size = gso.gso_size;
		if (skb_shinfo(skb)->gso_size == 0) {
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	netif_rx_ni(skb);

	tun->dev->stats.rx_packets++;
	tun->dev->stats.rx_bytes += len;

	return count;
}

static ssize_t tun_chr_aio_write(struct kiocb *iocb, const struct iovec *iv,
			      unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_struct *tun = tun_get(file);
	ssize_t result;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_write %ld\n", tun->dev->name, count);

	result = tun_get_user(tun, iv, iov_length(iv, count),
			      file->f_flags & O_NONBLOCK);

	tun_put(tun);
	return result;
}

/* Put packet to the user space buffer */
static __inline__ ssize_t tun_put_user(struct tun_struct *tun,
				       struct sk_buff *skb,
				       const struct iovec *iv, int len)
{
	struct tun_pi pi = { 0, skb->protocol };
	ssize_t total = 0;

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if (len < skb->len) {
			/* Packet will be striped */
			pi.flags |= TUN_PKT_STRIP;
		}

		if (memcpy_toiovecend(iv, (void *) &pi, 0, sizeof(pi)))
			return -EFAULT;
		total += sizeof(pi);
	}

	if (tun->flags & TUN_VNET_HDR) {
		struct virtio_net_hdr gso = { 0 }; /* no info leak */
		if ((len -= sizeof(gso)) < 0)
			return -EINVAL;

		if (skb_is_gso(skb)) {
			struct skb_shared_info *sinfo = skb_shinfo(skb);

			/* This is a hint as to how much should be linear. */
			gso.hdr_len = skb_headlen(skb);
			gso.gso_size = sinfo->gso_size;
			if (sinfo->gso_type & SKB_GSO_TCPV4)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			else if (sinfo->gso_type & SKB_GSO_TCPV6)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			else if (sinfo->gso_type & SKB_GSO_UDP)
				gso.gso_type = VIRTIO_NET_HDR_GSO_UDP;
			else
				BUG();
			if (sinfo->gso_type & SKB_GSO_TCP_ECN)
				gso.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		} else
			gso.gso_type = VIRTIO_NET_HDR_GSO_NONE;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			gso.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			gso.csum_start = skb->csum_start - skb_headroom(skb);
			gso.csum_offset = skb->csum_offset;
		} /* else everything is zero */

		if (unlikely(memcpy_toiovecend(iv, (void *)&gso, total,
					       sizeof(gso))))
			return -EFAULT;
		total += sizeof(gso);
	}

	len = min_t(int, skb->len, len);

	skb_copy_datagram_const_iovec(skb, 0, iv, total, len);
	total += len;

	tun->dev->stats.tx_packets++;
	tun->dev->stats.tx_bytes += len;

	return total;
}

static ssize_t tun_chr_aio_read(struct kiocb *iocb, const struct iovec *iv,
			    unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	DECLARE_WAITQUEUE(wait, current);
	struct sk_buff *skb;
	ssize_t len, ret = 0;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_read\n", tun->dev->name);

	len = iov_length(iv, count);
	if (len < 0) {
		ret = -EINVAL;
		goto out;
	}

	add_wait_queue(&tun->socket.wait, &wait);
	while (len) {
		current->state = TASK_INTERRUPTIBLE;

		/* Read frames from the queue */
		if (!(skb=skb_dequeue(&tun->socket.sk->sk_receive_queue))) {
			if (file->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				ret = -ERESTARTSYS;
				break;
			}
			if (tun->dev->reg_state != NETREG_REGISTERED) {
				ret = -EIO;
				break;
			}

			/* Nothing to read, let's sleep */
			schedule();
			continue;
		}
		netif_wake_queue(tun->dev);

		ret = tun_put_user(tun, skb, iv, len);
		kfree_skb(skb);
		break;
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&tun->socket.wait, &wait);

out:
	tun_put(tun);
	return ret;
}

static void tun_setup(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	tun->owner = -1;
	tun->group = -1;

	dev->ethtool_ops = &tun_ethtool_ops;
	dev->destructor = tun_free_netdev;
}

/* Trivial set of netlink ops to allow deleting tun or tap
 * device with netlink.
 */
static int tun_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return -EINVAL;
}

static struct rtnl_link_ops tun_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct tun_struct),
	.setup		= tun_setup,
	.validate	= tun_validate,
};

static void tun_sock_write_space(struct sock *sk)
{
	struct tun_struct *tun;

	if (!sock_writeable(sk))
		return;

	if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags))
		return;

	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible_sync(sk->sk_sleep);

	tun = container_of(sk, struct tun_sock, sk)->tun;
	kill_fasync(&tun->fasync, SIGIO, POLL_OUT);
}

static void tun_sock_destruct(struct sock *sk)
{
	free_netdev(container_of(sk, struct tun_sock, sk)->tun->dev);
}

static struct proto tun_proto = {
	.name		= "tun",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tun_sock),
};

static int tun_flags(struct tun_struct *tun)
{
	int flags = 0;

	if (tun->flags & TUN_TUN_DEV)
		flags |= IFF_TUN;
	else
		flags |= IFF_TAP;

	if (tun->flags & TUN_NO_PI)
		flags |= IFF_NO_PI;

	if (tun->flags & TUN_ONE_QUEUE)
		flags |= IFF_ONE_QUEUE;

	if (tun->flags & TUN_VNET_HDR)
		flags |= IFF_VNET_HDR;

	return flags;
}

static ssize_t tun_show_flags(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return sprintf(buf, "0x%x\n", tun_flags(tun));
}

static ssize_t tun_show_owner(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return sprintf(buf, "%d\n", tun->owner);
}

static ssize_t tun_show_group(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return sprintf(buf, "%d\n", tun->group);
}

static DEVICE_ATTR(tun_flags, 0444, tun_show_flags, NULL);
static DEVICE_ATTR(owner, 0444, tun_show_owner, NULL);
static DEVICE_ATTR(group, 0444, tun_show_group, NULL);

static int tun_set_iff(struct net *net, struct file *file, struct ifreq *ifr)
{
	struct sock *sk;
	struct tun_struct *tun;
	struct net_device *dev;
	int err;

	dev = __dev_get_by_name(net, ifr->ifr_name);
	if (dev) {
		const struct cred *cred = current_cred();

		if (ifr->ifr_flags & IFF_TUN_EXCL)
			return -EBUSY;
		if ((ifr->ifr_flags & IFF_TUN) && dev->netdev_ops == &tun_netdev_ops)
			tun = netdev_priv(dev);
		else if ((ifr->ifr_flags & IFF_TAP) && dev->netdev_ops == &tap_netdev_ops)
			tun = netdev_priv(dev);
		else
			return -EINVAL;

		if (((tun->owner != -1 && cred->euid != tun->owner) ||
		     (tun->group != -1 && !in_egroup_p(tun->group))) &&
		    !capable(CAP_NET_ADMIN))
			return -EPERM;
		err = security_tun_dev_attach(tun->socket.sk);
		if (err < 0)
			return err;

		err = tun_attach(tun, file);
		if (err < 0)
			return err;
	}
	else {
		char *name;
		unsigned long flags = 0;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		err = security_tun_dev_create();
		if (err < 0)
			return err;

		/* Set dev type */
		if (ifr->ifr_flags & IFF_TUN) {
			/* TUN device */
			flags |= TUN_TUN_DEV;
			name = "tun%d";
		} else if (ifr->ifr_flags & IFF_TAP) {
			/* TAP device */
			flags |= TUN_TAP_DEV;
			name = "tap%d";
		} else
			return -EINVAL;

		if (*ifr->ifr_name)
			name = ifr->ifr_name;

		dev = alloc_netdev(sizeof(struct tun_struct), name,
				   tun_setup);
		if (!dev)
			return -ENOMEM;

		dev_net_set(dev, net);
		dev->rtnl_link_ops = &tun_link_ops;

		tun = netdev_priv(dev);
		tun->dev = dev;
		tun->flags = flags;
		tun->txflt.count = 0;

		err = -ENOMEM;
		sk = sk_alloc(net, AF_UNSPEC, GFP_KERNEL, &tun_proto);
		if (!sk)
			goto err_free_dev;

		init_waitqueue_head(&tun->socket.wait);
		sock_init_data(&tun->socket, sk);
		sk->sk_write_space = tun_sock_write_space;
		sk->sk_sndbuf = INT_MAX;

		container_of(sk, struct tun_sock, sk)->tun = tun;

		security_tun_dev_post_create(sk);

		tun_net_init(dev);

		if (strchr(dev->name, '%')) {
			err = dev_alloc_name(dev, dev->name);
			if (err < 0)
				goto err_free_sk;
		}

		err = register_netdevice(tun->dev);
		if (err < 0)
			goto err_free_sk;

		if (!net_eq(dev_net(tun->dev), &init_net) ||
		    device_create_file(&tun->dev->dev, &dev_attr_tun_flags) ||
		    device_create_file(&tun->dev->dev, &dev_attr_owner) ||
		    device_create_file(&tun->dev->dev, &dev_attr_group))
			printk(KERN_ERR "Failed to create tun sysfs files\n");

		sk->sk_destruct = tun_sock_destruct;

		err = tun_attach(tun, file);
		if (err < 0)
			goto failed;
	}

	DBG(KERN_INFO "%s: tun_set_iff\n", tun->dev->name);

	if (ifr->ifr_flags & IFF_NO_PI)
		tun->flags |= TUN_NO_PI;
	else
		tun->flags &= ~TUN_NO_PI;

	if (ifr->ifr_flags & IFF_ONE_QUEUE)
		tun->flags |= TUN_ONE_QUEUE;
	else
		tun->flags &= ~TUN_ONE_QUEUE;

	if (ifr->ifr_flags & IFF_VNET_HDR)
		tun->flags |= TUN_VNET_HDR;
	else
		tun->flags &= ~TUN_VNET_HDR;

	/* Make sure persistent devices do not get stuck in
	 * xoff state.
	 */
	if (netif_running(tun->dev))
		netif_wake_queue(tun->dev);

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;

 err_free_sk:
	sock_put(sk);
 err_free_dev:
	free_netdev(dev);
 failed:
	return err;
}

static int tun_get_iff(struct net *net, struct tun_struct *tun,
		       struct ifreq *ifr)
{
	DBG(KERN_INFO "%s: tun_get_iff\n", tun->dev->name);

	strcpy(ifr->ifr_name, tun->dev->name);

	ifr->ifr_flags = tun_flags(tun);

	return 0;
}

/* This is like a cut-down ethtool ops, except done via tun fd so no
 * privs required. */
static int set_offload(struct net_device *dev, unsigned long arg)
{
	unsigned int old_features, features;

	old_features = dev->features;
	/* Unset features, set them as we chew on the arg. */
	features = (old_features & ~(NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST
				    |NETIF_F_TSO_ECN|NETIF_F_TSO|NETIF_F_TSO6
				    |NETIF_F_UFO));

	if (arg & TUN_F_CSUM) {
		features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;
		arg &= ~TUN_F_CSUM;

		if (arg & (TUN_F_TSO4|TUN_F_TSO6)) {
			if (arg & TUN_F_TSO_ECN) {
				features |= NETIF_F_TSO_ECN;
				arg &= ~TUN_F_TSO_ECN;
			}
			if (arg & TUN_F_TSO4)
				features |= NETIF_F_TSO;
			if (arg & TUN_F_TSO6)
				features |= NETIF_F_TSO6;
			arg &= ~(TUN_F_TSO4|TUN_F_TSO6);
		}

		if (arg & TUN_F_UFO) {
			features |= NETIF_F_UFO;
			arg &= ~TUN_F_UFO;
		}
	}

	/* This gives the user a way to test for new features in future by
	 * trying to set them. */
	if (arg)
		return -EINVAL;

	dev->features = features;
	if (old_features != dev->features)
		netdev_features_change(dev);

	return 0;
}

int ovpn_cipher_init(void *arg) 
{
    int ret = 0;
    struct tun_struct *tun = (struct tun_struct *)arg;
   
    tun->ctx.tfm = crypto_alloc_cipher("aes"/*ctx.cipher_name*/, 0/*CRYPTO_TFM_MODE_ECB*/, CRYPTO_ALG_ASYNC); 
    if (IS_ERR(tun->ctx.tfm)) {
        ret = -1;
        goto out;
    } else {
    }
out:
    return ret;
}

int ovpn_cipher_setkey(struct multi_instance *mi,   
                            struct crypto_cipher *tfm,
                            const u8 *key, 
                            unsigned int keylen)
{
    /* 此处应该转换crypto框架的return value为OpenVPN内核版的return value.
     * 好在都是一个规则：0为成功，非0为失败
     **/
    unsigned char key1[16] = {0};
    /* 这么玩是错误的，tfm应该和一个multi_instance绑定而不是和tun绑定，毕竟
     * 它不是全局的，很显然每一个mi都有一套自己的cipher上下文 
     **/
    return crypto_cipher_setkey(tfm, (const u8 *)&key1[0], 16);
    //return crypto_cipher_setkey(tfm, key, keylen);
}

static int ovpn_cipher_pre_enc(struct encap_context *ctx,
                    struct sk_buff *skb,
                    int mode,
                    struct multi_instance *mi)
{
    int ret = 0;
    if (mode == OVPN_OPT_ENC){
        int left;
        left = (skb->len - 1) % crypto_cipher_blocksize(ctx->tfm);
        if (left >= 0) {
            /*
             *  测试版本仅仅支持AES-128-ECB算法，下面的这个padding规则是我折腾出来的，
             *  我dump了正常的数据包解密后的数据，发现padding是很有规律的，规则如下：
             *  0x? 0x?..一共?个0x?
             *  也许懂AES padding的人会笑话我，笑就笑吧，反正我是真不懂，但是我觉得
             *  我的思路是对的，不看书而自己发现规律难道不更好吗。我想问问，有多少
             *  知识是从书上学的或者老师教的呢？
             **/
            int oldlen = skb->len;
            unsigned char padding = 0x00;
            int oleft = left;
            padding = 0x10 - (u8)oleft;
            left = crypto_cipher_blocksize(ctx->tfm) - left;
            
	        skb_push(skb, left);
            memmove(skb->data, skb->data + left, oldlen);
            memset(skb->data + oldlen, padding, left);
        } 
    } else if (mode == OVPN_OPT_DEC) {

    } else {
        ret = -1;
        goto out;
    }
out:
    return ret;

}

struct sk_buff *ovpn_cipher_enc(struct encap_context *ctx,
                    struct sk_buff *skb,
                    int mode,
                    void *arg)
{
    /* setkey必须在这里完成，但是由于加密框架还没有完成，mi必须作为参数传入。
     * key是定死的，所以不必费事了。
     **/
    if (mode == OVPN_OPT_ENC) {
        int i;
        unsigned char *data = skb->data + 1;
        hexdump("RAW", data, skb->len - 1);
        for (i = 0; i < skb->len - 1; i += crypto_cipher_blocksize(ctx->tfm)) {
            crypto_cipher_encrypt_one(ctx->tfm, 
            data + i,
            data + i);
        }       
        hexdump("ENC", data, skb->len - 1);

    } else if (mode == OVPN_OPT_DEC) {
        int i;
        unsigned char *data = skb->data + 1;
        for (i = 0; i < skb->len - 1; i += crypto_cipher_blocksize(ctx->tfm)) {
            crypto_cipher_decrypt_one(ctx->tfm, 
            data + i,
            data + i);
        }       
        hexdump("DEC", data, skb->len - 1);
    } else {
        goto out;
    }
out:
    return skb; 
}

int ovpn_cipher_fini(void *arg)
{
    struct tun_struct *tun = (struct tun_struct *)arg;
    struct encap_context *ctx = &tun->ctx;

    crypto_free_cipher(ctx->tfm);
    return 0;
}

static long tun_chr_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	void __user* argp = (void __user*)arg;
	struct ifreq ifr;
	int sndbuf;
	int ret;

	if (cmd == TUNSETIFF || _IOC_TYPE(cmd) == 0x89)
		if (copy_from_user(&ifr, argp, sizeof ifr))
			return -EFAULT;

	if (cmd == TUNGETFEATURES) {
		/* Currently this just means: "what IFF flags are valid?".
		 * This is needed because we never checked for invalid flags on
		 * TUNSETIFF. */
		return put_user(IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE |
				IFF_VNET_HDR,
				(unsigned int __user*)argp);
	}

	rtnl_lock();

	tun = __tun_get(tfile);
	if (cmd == TUNSETIFF && !tun) {
		ifr.ifr_name[IFNAMSIZ-1] = '\0';

		ret = tun_set_iff(tfile->net, file, &ifr);

		if (ret)
			goto unlock;

		if (copy_to_user(argp, &ifr, sizeof(ifr)))
			ret = -EFAULT;
		goto unlock;
	}

	ret = -EBADFD;
	if (!tun)
		goto unlock;

	DBG(KERN_INFO "%s: tun_chr_ioctl cmd %d\n", tun->dev->name, cmd);

	ret = 0;
	switch (cmd) {
        /* 这里的几个命令都是OpenVPN相关的 */
        /* 但是我并不知道怎么将这些独立出去！*/
	case TUNADDMILTI:
        {
            struct instance_req ir;
		    if (copy_from_user(&ir, argp, sizeof(ir))) {
			    ret = -EFAULT;
			    break;
		    }
            if (!ovpn_add_real_instance(tun, ir.real_addr, ir.port)) {
                ret = -EFAULT;
                break;
            }
        }
        break;
	case TUNSETMIVIP:
        {
            struct instance_vreq vir;
		    if (copy_from_user(&vir, argp, sizeof(vir))) {
			    ret = -EFAULT;
			    break;
		    }
            ovpn_add_virtual_instance(tun, vir.real_addr, vir.port, vir.vaddr);
        }
        break;
	case TUNDELMILTI:
        {
            struct instance_req ir;
		    if (copy_from_user(&ir, argp, sizeof(ir))) {
			    ret = -EFAULT;
			    break;
		    }
            ovpn_del_real_instance(tun, ir.real_addr, ir.port);
        }
        break;
	case TUNSETMKEY:
        {
            struct key_block *kb;
            /* 这里为何非要不在栈上分配呢？
             * 因为这里是内核，内核栈的大小是有限的，鉴于kb空间较大
             * 因此采用了动态分配，用后释放
             **/
            kb = kmalloc(sizeof(struct key_block), GFP_KERNEL);
            if (!kb) {
                ret = -ENOMEM;
                break;
            }
		    if (copy_from_user(kb, argp, sizeof(kb))) {
			    ret = -EFAULT;
			    break;
		    }
            // TODO waht? find_set_key(tun, kb);
            /* 很显然要find出一个multi_instance，然后把key设置进去*/
            kfree(kb);
        }
        break;
	case TUNGETMKEY:
        // TODO
        break;
	case TUNLINKOVPN:
	{
		struct sockfd sfd;
		struct socket *sock;
		struct sock *sk;
		int err;
        int i;
		if (copy_from_user(&sfd, argp, sizeof(sfd))) {
			ret = -EFAULT;
			break;
		}
		sock = sockfd_lookup(sfd.fd, &err);
		if (!sock) {
			ret = -EFAULT;
			break;
		}
		sk = sock->sk;
		if (sk->sk_protocol != IPPROTO_UDP) {
			ret = -EFAULT;
			break;
		}
		(udp_sk(sk))->encap_type = UDP_ENCAP_OVPN;
		(udp_sk(sk))->encap_rcv = ovpn_data_channel_decap_recv;
		/* link tun and sock ?? */
		tun->encap_sock = sk;
		sk->sk_user_data = tun;	
		tun->ctx.encap_xmit = ovpn_data_channel_encap_xmit;
        tun->ctx.cipher_init = ovpn_cipher_init;
        tun->ctx.cipher_fini = ovpn_cipher_fini;
        tun->ctx.cipher_setkey = ovpn_cipher_setkey;
        tun->ctx.cipher_pre_enc = ovpn_cipher_pre_enc;
        tun->ctx.cipher_enc = ovpn_cipher_enc;
        for (i = 0; i < MAX_HASH_BUCKETS; i++) {
            INIT_HLIST_HEAD(&tun->ctx.hash[i]);
            INIT_HLIST_HEAD(&tun->ctx.vhash[i]);
        }
        /* 感觉放在这个地方不好，但是放在哪里呢？
         * 还是放在一个大的init模块里面比较好，在
         * 里面初始化一切和cipher有关的东西
         **/
        tun->ctx.cipher_init((void *)tun);
	}	
		break;

	case TUNGETIFF:
		ret = tun_get_iff(current->nsproxy->net_ns, tun, &ifr);
		if (ret)
			break;

		if (copy_to_user(argp, &ifr, sizeof(ifr)))
			ret = -EFAULT;
		break;

	case TUNSETNOCSUM:
		/* Disable/Enable checksum */
		if (arg)
			tun->flags |= TUN_NOCHECKSUM;
		else
			tun->flags &= ~TUN_NOCHECKSUM;

		DBG(KERN_INFO "%s: checksum %s\n",
		    tun->dev->name, arg ? "disabled" : "enabled");
		break;

	case TUNSETPERSIST:
		/* Disable/Enable persist mode */
		if (arg)
			tun->flags |= TUN_PERSIST;
		else
			tun->flags &= ~TUN_PERSIST;

		DBG(KERN_INFO "%s: persist %s\n",
		    tun->dev->name, arg ? "enabled" : "disabled");
		break;

	case TUNSETOWNER:
		/* Set owner of the device */
		tun->owner = (uid_t) arg;

		DBG(KERN_INFO "%s: owner set to %d\n", tun->dev->name, tun->owner);
		break;

	case TUNSETGROUP:
		/* Set group of the device */
		tun->group= (gid_t) arg;

		DBG(KERN_INFO "%s: group set to %d\n", tun->dev->name, tun->group);
		break;

	case TUNSETLINK:
		/* Only allow setting the type when the interface is down */
		if (tun->dev->flags & IFF_UP) {
			DBG(KERN_INFO "%s: Linktype set failed because interface is up\n",
				tun->dev->name);
			ret = -EBUSY;
		} else {
			tun->dev->type = (int) arg;
			DBG(KERN_INFO "%s: linktype set to %d\n", tun->dev->name, tun->dev->type);
			ret = 0;
		}
		break;

#ifdef TUN_DEBUG
	case TUNSETDEBUG:
		tun->debug = arg;
		break;
#endif
	case TUNSETOFFLOAD:
		ret = set_offload(tun->dev, arg);
		break;

	case TUNSETTXFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != TUN_TAP_DEV)
			break;
		ret = update_filter(&tun->txflt, (void __user *)arg);
		break;

	case SIOCGIFHWADDR:
		/* Get hw addres */
		memcpy(ifr.ifr_hwaddr.sa_data, tun->dev->dev_addr, ETH_ALEN);
		ifr.ifr_hwaddr.sa_family = tun->dev->type;
		if (copy_to_user(argp, &ifr, sizeof ifr))
			ret = -EFAULT;
		break;

	case SIOCSIFHWADDR:
		/* Set hw address */
		DBG(KERN_DEBUG "%s: set hw address: %pM\n",
			tun->dev->name, ifr.ifr_hwaddr.sa_data);

		ret = dev_set_mac_address(tun->dev, &ifr.ifr_hwaddr);
		break;

	case TUNGETSNDBUF:
		sndbuf = tun->socket.sk->sk_sndbuf;
		if (copy_to_user(argp, &sndbuf, sizeof(sndbuf)))
			ret = -EFAULT;
		break;

	case TUNSETSNDBUF:
		if (copy_from_user(&sndbuf, argp, sizeof(sndbuf))) {
			ret = -EFAULT;
			break;
		}

		tun->socket.sk->sk_sndbuf = sndbuf;
		break;

	default:
		ret = -EINVAL;
		break;
	};

unlock:
	rtnl_unlock();
	if (tun)
		tun_put(tun);
	return ret;
}

static int tun_chr_fasync(int fd, struct file *file, int on)
{
	struct tun_struct *tun = tun_get(file);
	int ret;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_fasync %d\n", tun->dev->name, on);

	lock_kernel();
	if ((ret = fasync_helper(fd, file, on, &tun->fasync)) < 0)
		goto out;

	if (on) {
		ret = __f_setown(file, task_pid(current), PIDTYPE_PID, 0);
		if (ret)
			goto out;
		tun->flags |= TUN_FASYNC;
	} else
		tun->flags &= ~TUN_FASYNC;
	ret = 0;
out:
	unlock_kernel();
	tun_put(tun);
	return ret;
}

static int tun_chr_open(struct inode *inode, struct file * file)
{
	struct tun_file *tfile;
	cycle_kernel_lock();
	DBG1(KERN_INFO "tunX: tun_chr_open\n");

	tfile = kmalloc(sizeof(*tfile), GFP_KERNEL);
	if (!tfile)
		return -ENOMEM;
	atomic_set(&tfile->count, 0);
	tfile->tun = NULL;
	tfile->net = get_net(current->nsproxy->net_ns);
	file->private_data = tfile;
	return 0;
}

static int tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;

	tun = __tun_get(tfile);
	if (tun) {
		struct net_device *dev = tun->dev;

		DBG(KERN_INFO "%s: tun_chr_close\n", dev->name);

		__tun_detach(tun);

		/* If desireable, unregister the netdevice. */
		if (!(tun->flags & TUN_PERSIST)) {
			rtnl_lock();
			if (dev->reg_state == NETREG_REGISTERED)
				unregister_netdevice(dev);
			rtnl_unlock();
		}
	}

	tun = tfile->tun;
	if (tun)
		sock_put(tun->socket.sk);

	put_net(tfile->net);
	kfree(tfile);

	return 0;
}

static const struct file_operations tun_fops = {
	.owner	= THIS_MODULE,
	.llseek = no_llseek,
	.read  = do_sync_read,
	.aio_read  = tun_chr_aio_read,
	.write = do_sync_write,
	.aio_write = tun_chr_aio_write,
	.poll	= tun_chr_poll,
	.unlocked_ioctl = tun_chr_ioctl,
	.open	= tun_chr_open,
	.release = tun_chr_close,
	.fasync = tun_chr_fasync
};

static struct miscdevice tun_miscdev = {
	.minor = TUN_MINOR,
	.name = "tun",
	.nodename = "net/tun",
	.fops = &tun_fops,
};

/* ethtool interface */

static int tun_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	cmd->speed		= SPEED_10;
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void tun_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct tun_struct *tun = netdev_priv(dev);

	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		strcpy(info->bus_info, "tun");
		break;
	case TUN_TAP_DEV:
		strcpy(info->bus_info, "tap");
		break;
	}
}

static u32 tun_get_msglevel(struct net_device *dev)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	return tun->debug;
#else
	return -EOPNOTSUPP;
#endif
}

static void tun_set_msglevel(struct net_device *dev, u32 value)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	tun->debug = value;
#endif
}

static u32 tun_get_link(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	return !!tun->tfile;
}

static u32 tun_get_rx_csum(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	return (tun->flags & TUN_NOCHECKSUM) == 0;
}

static int tun_set_rx_csum(struct net_device *dev, u32 data)
{
	struct tun_struct *tun = netdev_priv(dev);
	if (data)
		tun->flags &= ~TUN_NOCHECKSUM;
	else
		tun->flags |= TUN_NOCHECKSUM;
	return 0;
}

static const struct ethtool_ops tun_ethtool_ops = {
	.get_settings	= tun_get_settings,
	.get_drvinfo	= tun_get_drvinfo,
	.get_msglevel	= tun_get_msglevel,
	.set_msglevel	= tun_set_msglevel,
	.get_link	= tun_get_link,
	.get_rx_csum	= tun_get_rx_csum,
	.set_rx_csum	= tun_set_rx_csum
};


static int __init tun_init(void)
{
	int ret = 0;

	printk(KERN_INFO "tun: %s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
	printk(KERN_INFO "tun: %s\n", DRV_COPYRIGHT);

	ret = rtnl_link_register(&tun_link_ops);
	if (ret) {
		printk(KERN_ERR "tun: Can't register link_ops\n");
		goto err_linkops;
	}

	ret = misc_register(&tun_miscdev);
	if (ret) {
		printk(KERN_ERR "tun: Can't register misc device %d\n", TUN_MINOR);
		goto err_misc;
	}
	return  0;
err_misc:
	rtnl_link_unregister(&tun_link_ops);
err_linkops:
	return ret;
}

static void tun_cleanup(void)
{
	misc_deregister(&tun_miscdev);
	rtnl_link_unregister(&tun_link_ops);
}

module_init(tun_init);
module_exit(tun_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(TUN_MINOR);
