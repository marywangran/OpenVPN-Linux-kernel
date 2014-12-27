/*
 * 
 */
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <net/net_namespace.h>

#include <net/netfilter/nf_conntrack.h>

#include "ovpn_func.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wangran <marywangran@126.com>");
MODULE_DESCRIPTION("OpenVPN connection helper");
MODULE_ALIAS("ip_conntrack_ovpn");
MODULE_ALIAS_NFCT_HELPER("ovpn");

/* 
 * 此端口难道就这么写死成1194吗？难道不是需要注册的吗 :(
 **/
#define OVPN_PORT	1194


struct ovpn_instance {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be32 packet_id;
    /* 请恕我这么写，反正没有实际实现 */
	unsigned char *info[0];
};

/* fake struct nf_conn_counter*/
struct instance_info {
	u_int64_t i;
	u_int64_t j;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be32 packet_id;
};

/* 真实的packet_id应该从慢速路径或者控制路径的Netlink消息传递到conn的extend中 */
__be32 static_fake_packet_id = 0;


static int ovpn_nf_pre_routing(struct sk_buff *skb)
{
	/* nothing to do */
	return NF_ACCEPT;
}

/* 第二个参数真的需要吗，因为加密所需要的cipher_info以及封装需要的udp头，ip头信息全部
 * 而不是部分地保存在了conntrack info信息中了啊啊啊
 *
 * 注意：这里的参数并不符合规范，因为我盗取了heler的结构体，但是思想是一致的！
 **/
static int encap_xmit(struct sk_buff *skb, struct ovpn_instance *ovpn)
{
	/*
	 * 正如我一贯的风格，我总是无情推翻昨天的自大，将欢乐瞬间变成悲哀
	 * 我没有调用ovpn_data_channel_encap_xmit这个tun网卡的HOOK函数，因为
	 * 我觉得太垃圾了，其实我正在逐步还原tun.c，就像这次一样，我力图使用
	 * Netfilter进行短路操作，而不再触摸tun.c以及UDP socket。就像你看到
	 * 的那样，你依然可以加载系统自带的原生态tun.ko
	 **/
	int ret = NF_DROP;
    int copy = 0;
    unsigned int max_headroom;
	struct sk_buff *skb_to_encap;
	__be32 saddr = ovpn->saddr;
	__be32 daddr = ovpn->daddr;
	__be16 sport = ovpn->sport;
	__be16 dport = ovpn->dport;
	__be32 packet_id = ovpn->packet_id;
	struct iphdr *old = ip_hdr(skb);
	/* but 怎么判断OpenVPN是UDP的 
     * 很简单，一切都在nf_conn的extend中，
     * 只是，我这里没有写而已！
     **/

#define I_THINK_THIS_LENGTH_ENOUGH_BECAUSE_OF_XXX  78    
	max_headroom = (I_THINK_THIS_LENGTH_ENOUGH_BECAUSE_OF_XXX +  
				    sizeof(struct iphdr)                +
				    sizeof(struct udphdr)               +
				    sizeof(struct ovpnhdr));

    if (skb_headroom(skb) < max_headroom || !skb_clone_writable(skb, 0)) {
        struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
        if (!new_skb) {
            goto out;
        }
        skb_dst_set(new_skb, skb_dst(skb));

        skb_to_encap = new_skb;
        copy = 1;
    } else {
        skb_to_encap = skb;
	}
	/* ##################### encap OpenVPN #################### */
	{
        struct ovpnhdr *ohdr;
		skb_push(skb_to_encap, sizeof(struct ovpnhdr));
	    ohdr = ovpn_hdr(skb_to_encap);
		/* 慢速路径的packet_id必须反映到快速路径中来！！ */
	    ohdr->id = htonl(packet_id);
	    ohdr->ocode = (P_DATA_V1 << P_OPCODE_SHIFT) | 0x0;
	}
	/* ##################### encap UDP #################### */
	{
		struct udphdr *uh;
	
		skb_push(skb_to_encap, sizeof(struct udphdr));
		skb_reset_transport_header(skb_to_encap);

		uh = udp_hdr(skb_to_encap);
		uh->source = sport;
		uh->dest = dport;
		uh->len = htons(skb_to_encap->len);
		uh->check = 0;
		uh->check = csum_tcpudp_magic(saddr, daddr, skb_to_encap->len,
								IPPROTO_UDP, csum_partial(uh,
						                                   skb_to_encap->len, 
							                                0));
	}
	/* ##################### encap IP #################### */
	{
		struct iphdr *iph;
		struct dst_entry *dst;

		skb_push(skb_to_encap, sizeof(struct iphdr));
		skb_reset_network_header(skb_to_encap);
		iph = ip_hdr(skb_to_encap);
		iph->version		=	4;
		iph->ihl		=	sizeof(struct iphdr)>>2;
		iph->frag_off		=	0;//old->frag_off;
		iph->protocol		=	IPPROTO_UDP;
		iph->tos		=	old->tos;
		iph->daddr		=	daddr;
		iph->saddr		=	saddr;
		iph->ttl		=	old->ttl;
		/* 这个reroute频繁用于OUTPUT Netfilter HOOK，但问Rusty本人，
		 * Netfilter的OUTPUT设计为何如何之好 */
		if (ip_route_me_harder(skb_to_encap, RTN_LOCAL)!= 0) {
			/* 无论如何都要STOLEN的 */
            if (copy) {
			    kfree_skb(skb_to_encap);	
            }
			goto out;
		}
		dst = skb_dst(skb_to_encap);	

		ip_select_ident(iph, dst, NULL);
	}
	ip_local_out(skb_to_encap);
    /* 偷走数据包，不再在曾经的路上继续 */
    ret = NF_STOLEN;
out:
	return ret;

}

static unsigned int ipv4_ovpn_in_local( unsigned int hook,
									struct sk_buff *skb,
									const struct net_device *in,
									const struct net_device *out,
									int (*okfn)(struct sk_buff *))
{
    int ret = NF_ACCEPT;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct net_device *dev = NULL;
    struct tun_struct *tun = NULL;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		goto out;
	}
	if (ct == &nf_conntrack_untracked) {
		goto out;
	}

	dev = dev_get_by_name(&init_net, "tun0");
	if (!dev) {
		goto out_not_put;
	}

    tun = netdev_priv(dev);;
	if (!tun) {
		goto out;
	}

	if (out && dev == out) {	
		/* 
		 * 这里要取出保存在conn中的所有信息，包括加密密钥
		 */
        /*
		 * cipher_info = (struct instance_info *)nf_conn_acct_find(ct);
		 * if (cipher_info != NULL) {  
		 * 	if (cipher_info->saddr != 0 &&
		 *			cipher_info->daddr != 0) {
         */
				struct ovpn_instance ovpn;
				ovpn.saddr = 0x32c7a8c0;/*cipher_info->daddr;*/
				ovpn.daddr = 0xe9c7a8c0;/*cipher_info->saddr;*/
				ovpn.sport = 0xaa04;/*cipher_info->dport;*/
				ovpn.dport = 0xaa04;/*cipher_info->sport;*/
				++ static_fake_packet_id;/*cipher_info->packet_id;*/
				ovpn.packet_id = static_fake_packet_id;/*cipher_info->packet_id;*/
				ret = encap_xmit(skb, &ovpn);
				goto out;	

	} 
out:
    dev_put(dev);
out_not_put:
    return ret;
}
static unsigned int ipv4_ovpn_in( unsigned int hook,
									struct sk_buff *skb,
									const struct net_device *in,
									const struct net_device *out,
									int (*okfn)(struct sk_buff *))
{
	int ret = NF_ACCEPT;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct iphdr *hdr = ip_hdr(skb);
	struct udphdr *uh;
	struct net_device *dev = NULL;
    struct tun_struct *tun = NULL;
	__be32 saddr, daddr;
	__be16 sport, dport;
	int dir;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		goto out;
	}
	if (ct == &nf_conntrack_untracked) {
		goto out;
	}

	dev = dev_get_by_name(&init_net, "tun0");
	if (!dev) {
		goto out_not_put;
	}

	if ((in && in == dev) || (in && in == init_net.loopback_dev)) {
		goto out;
	}

    tun = netdev_priv(dev);;
	if (!tun) {
		goto out;
	}

    switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TAP_DEV:
		goto out;
	}

	saddr = hdr->saddr;
	daddr = hdr->daddr;

	/* 到达此处的数据包有以下几类：
	 *	1.正方向的UDP到将欲到达OpenVPN的数据包
	 *		1.1.控制通道数据包
	 *			这类数据包将最终穿过INPUT，完成conntrack的confirm，至此conntrack建立
	 *		1.2.数据通道的数据包
	 *			这类数据包就是我要截获，解密，进而STOLEN的。This is it！！！
	 *	2.从OpenVPN进程socket发出的数据包
	 *		2.1.控制通道数据包
	 *			这类数据包来自OpenVPN进程，用于SSL握手以及PING(keepablive)
	 *		2.2.数据通道数据包
	 *			这类数据包本来来自OpenVPN进程，由其加密，但是由于它们将在tun的xmit中被截获自行进行OpenVPN/UDP/IP封装，
	 *			因此并不会到达此处，也可以在OUTPUT/PREROUTING中被识别并自行进行OpenVPN/UDP/IP封装并被STOLEN到dev_queue_xmit
	 *			......
	 *
	 **/
	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL) {
		goto check_encap_xmit;
	}
	/* 此处没加锁啊没加锁！！！ */
	if (hdr->protocol != IPPROTO_UDP) {
	/*
	 * 这里彻底呈现了UDP的优势
	 * 你可能不信！但是如果是TCP，你将不能在中间任何地方截获(STOLEN)数据！
	 * 因为TCP是端到端流协议，你要是截获了数据，怎么发送回执？？
	 * 你没法ACK数据，TCP将不再继续！除非...
	 * 除非你连ACK也伪造！连带的，你难道要自己实现TCP的语义？？ 
	 **/
		goto check_encap_xmit;
	}

    skb_pull(skb, ip_hdrlen(skb));
	skb_reset_transport_header(skb);
	/* 此处省略了UDP接收的例行校验检查 */
	uh = udp_hdr(skb);
			
	if (uh->dest != htons(OVPN_PORT)) {
		skb_push(skb, ip_hdrlen(skb));
		skb_reset_network_header(skb);
		goto check_encap_xmit;
	}
	sport = uh->source;
	dport = uh->dest;
	{
		/*
		 *  这里要取出保存在conn中的所有信息，包括解密密钥
		 *	ct_inner = nf_ct_get(skb, &ctinfo_inner);
		 *	cipher_info = nf_conn_acct_find((const struct nf_conn *)ct_inner);
		 *	if (cipher_info == NULL) {  
		 *		...
		 *		...
		 *
		 */
	}	
    /* decrypt 
     * 很显然，这是关键！数据解密！
     * 但是谁能告诉我内核中怎么高效使用加解密，如果不能高效，
     * 那么起码保证灵活，就像OpenSSL那样！进入了内核态，我突然
     * 突然想到了OpenSSL的好，人，不能忘本啊  :<
     */
	/*
	 *  以上是我在udp_encap_rcv版本中的注释！！但是，但是
	 *  天啊！饶恕我的贪婪吧！
	 *  在nf_conntrack_helper版本中，我连封装的力气都没有了，为了尽快验证，
	 *  我将代码写死！
	 *  解密算法：AES-128-ECB
	 *  解密密钥：128位的0！
	 */
	/* ################################################################### */
	/* 验证伊始，推进一个udp头 */
	skb_pull(skb, sizeof(struct udphdr));
	{
		/* PRE Decrypt--对齐数据，验证操作码 */
	    u8 *data = skb->data;
	    u8 ocode = data[0];
	    int op = ocode >> P_OPCODE_SHIFT;
	    if (op != P_DATA_V1) {
			skb_push(skb, sizeof(struct udphdr));
			skb_push(skb, ip_hdrlen(skb));
			skb_reset_network_header(skb);
			skb_reset_transport_header(skb);
		    goto out;		
	    }
	}
	/* ################################################################### */
	{
		/* Decrypt--调用内核接口解密数据 */
        /*int i;
		struct crypto_cipher *tfm;
		unsigned char key1[16] = {0};
        unsigned char *data;

		tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC); 
		if (!tfm) {
			return NF_DROP;
		}
		crypto_cipher_setkey(tfm, (const u8 *)&key1[0], 16);
        data = skb->data + 1;
        for (i = 0; i < skb->len - 1; i += crypto_cipher_blocksize(tfm)) {
            crypto_cipher_decrypt_one(tfm, data + i, data + i);
        }       
		crypto_free_cipher(tfm);
		*/
		/* 解密完成，推进一个OpenVPN头的长度 */
		skb_pull(skb, sizeof(struct ovpnhdr));
	}
	/* ################################################################### */

    switch (tun->flags & TUN_TYPE_MASK) {
    case TUN_TUN_DEV:
        switch (skb->data[0] & 0xf0) {
                /* 当前只支持IPv4 */
        case 0x40:
            break;
        default:
			/* 解密发现不是IPv4，不再恢复skb指针 */
			ret = NF_DROP;
            goto out;
                    
        }
        skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb_reset_transport_header(skb);
            /* 是时候丢掉西装外衣了，口袋里的通行证会将你引入深渊，
             * 不信的话，注释此言，在OpenVPN客户端机器上ping一下
             * 服务端的虚拟IP试一试 
             **/
        skb_dst_drop(skb);
        skb->protocol = htons(ETH_P_IP);;
        skb->dev = dev;
        ret = NF_STOLEN;
        break;
    }

    /* 模拟TUN虚拟网卡接收，此时截获处理正式完成，
     * 告诉UDP，嗨，你的数据我已经帮你处理了 
     **/
	/*	遍历PREROUTING旨在创建被OpenVPN封装流量的conntrack，
	 *	因为只有在这里才能从OpenVPN数据通道的conntrack中的info信息得到加密密钥：
	 *	1.该类流量在netif_rx_ni->netif_receive_skb->ip_rcv...路径中径直通过PREROUTING；
	 *	2.该类流量的reply流量直接使用其conntrack info中的加密密钥进行加密
	 **/
	nf_reset(skb);
    /* 溜达溜达，一直溜达到skb的conntrack被设置，所以我使用了带有condition的版本 */
	NF_HOOK_COND(PF_INET, NF_INET_PRE_ROUTING, skb, skb->dev, NULL,
						ovpn_nf_pre_routing, skb->nfct != NULL);
	{
		/*struct nf_conn *ct_inner;*/
		/*enum ip_conntrack_info ctinfo_inner;*/
		/*struct instance_info *cipher_info; */
		/* OK! 此时的ct应该就是OpenVPN裸skb的ct了！ */
		/*
		 *  注意，这里可能比较绕！对于ct_inner，很显然它是OpenVPN数据协议封装的内部skb的ct，那么
		 *  它的方向有两个，一个是正一个反，
		 *  1.对于正方向，很显然它是我们在上面的ovpn_nf_pre_routing
		 *	  这个fake HOOK中建立的，理所当然它的cipher_info就是在这里创建的
		 *	2.对于反方向，它走的是慢速路径，即它走的是OpenVPN进程（这是为什么呢？为什么呢？
		 *			因为：
		 *				skb来自某个物理网口，显然最终它要从tun0中xmit出去，这一路上它是不可能获得
		 *				任何关于multi_instance的信息的，所以只好走入慢速路径中，由OpenVPN进程从字符
		 *				设备读取该数据包，然后由OpenVPN进程加密，封装，传输之）
		 *	  只要有反向发起的数据包的正向(即从OpenVPNclient到OpenVPNserver方向)返回包经由此处，它将
		 *	  建立cipher_info。
		 *	因此，此处并不区分对待ct的方向！
		 **/

        /*
		ct_inner = nf_ct_get(skb, &ctinfo_inner);
		cipher_info = (struct instance_info *)nf_conn_acct_find((const struct nf_conn *)ct_inner);
		if (cipher_info == NULL) {  
			cipher_info = (struct instance_info *)nf_ct_acct_ext_add(ct_inner, GFP_ATOMIC);  
			if (cipher_info == NULL) {
				ret = NF_DROP;
				goto out;
			}  
			goto alloc_info;
		} else {
			// 注意：最终的成型info extend中，需要在destroy里面释放 JUST test!!
			if (cipher_info->saddr == 0 && cipher_info->daddr == 0) {
alloc_info:
				cipher_info->saddr = saddr;
				cipher_info->daddr = daddr;
				cipher_info->sport = sport;
				cipher_info->dport = dport;
				// info 就是cipher 
			}
		}
        */    
	}
    /* 真是谢天谢地！谢什么？答曰：
     * 在调用netif_rx的时候竟然还能保留nf信息，比如保留nf_conn...
     * 其实这也没什么大不了的，难道bridge模块没有这么玩吗？难道bonding，vlan没有这么玩吗？
     * 如果你不懂，没关系，试试看: 
     * sysctl -w net.bridge.bridge-nf-call-iptables=1
     * 然后跟一下代码...
     **/
	netif_rx_ni(skb);
    goto out;

check_encap_xmit:
    /* 此处find conntrack的info信息，如果数据包从物理网卡接收，最终需要通过tun网卡发出进行加密，那么：
     * 1.该数据包所属的流在从OpenVPN客户端过来的时候在PREROUTING中被解密，然后在PREROUTING中溜达到conn创建，
     *   此时，该流可以查到，直接取出info信息，调用encap_xmit进行加密；
     * 2.该数据包所属的流是主动从OpenVPN服务端发往OpenVPN客户端方向的，那么它在这个HOOK就应该直接返回，进入
     *   OpenVPN这个慢速路径进行加密，如果有从OpenVPN客户端回来的包，那么在这个HOOK中就会被在conntrack的info
     *   中设置info信息。
     * :)也已经深了，我以上如此清晰的思路想必可以代替代码吧，此处我就直接通过了。
     **/
    {
        int check = 0; /* 真正的check！ */
        if (check) {
			struct ovpn_instance ovpn;
            ret = encap_xmit(skb, &ovpn);
        }
    }

out:
	dev_put(dev);
out_not_put:
    return ret;
}

static struct nf_hook_ops ipv4_ovpn_ops[] __read_mostly = {
	{	.hook		= ipv4_ovpn_in,
		.owner		= THIS_MODULE,
		.pf		=	NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
	{	.hook		= ipv4_ovpn_in_local,
		.owner		= THIS_MODULE,
		.pf		=	NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
};


static void nf_conntrack_openvpn_fini(void)
{
	nf_unregister_hooks(ipv4_ovpn_ops, ARRAY_SIZE(ipv4_ovpn_ops));
}

static int __init nf_conntrack_openvpn_init(void)
{
	int ret = 0;

	ret = nf_register_hooks(ipv4_ovpn_ops, ARRAY_SIZE(ipv4_ovpn_ops)); 
	if (ret) {
		printk("nf_ct_ovpn: failed to register\n");
		return ret;
	}
		printk("nf_ct_ovpn: OKOK\n");
	return 0;
}

module_init(nf_conntrack_openvpn_init);
module_exit(nf_conntrack_openvpn_fini);
