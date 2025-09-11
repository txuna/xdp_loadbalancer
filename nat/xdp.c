//go:build ignore

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// #include "bpf_endian.h"
#include "common.h"

#define SERVER_NUM 2
#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent

char _license[] SEC("license") = "GPL";

int client_ip = bpf_htonl(0xa000001);
__u8 client_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x1};

int load_balancer_ip = bpf_htonl(0xa00000a);
__u8 load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x10};

struct server_config {
	__u32 ip;
	__u8 mac[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SERVER_NUM);
	__type(key, __u32);
	__type(value, struct server_config);
} servers SEC(".maps");

struct event {
	__u32 kind;
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	__u32 src_ip; 
	__u32 dst_ip; 
	__u16 src_port;
	__u16 dst_port;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
tcph_csum(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
    // Clear checksum
    tcph->check = 0;

    // Pseudo header checksum calculation
    __u32 sum = 0;
    sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
    sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
    sum += __constant_htons(IPPROTO_TCP);
    sum += __constant_htons((__u16)(data_end - (void *)tcph));

    // TCP header and payload checksum
    #pragma clang loop unroll_count(MAX_TCP_CHECK_WORDS)
    for (int i = 0; i <= MAX_TCP_CHECK_WORDS; i++) {
        __u16 *ptr = (__u16 *)tcph + i;
        if ((void *)ptr + 2 > data_end)
            break;
        sum += *(__u16 *)ptr;
    }

    // fold into 16 bit
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
	if (csum <= 0) {
		bpf_printk("csum is minus");
	}
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx){
	bpf_printk("vlan !!!!!\n");
	return XDP_PASS;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;
	struct event *es;

	// bpf_printk("xdp loadbalancer received packet!"); 

	struct ethhdr *eth = data;
	if ((void*)(eth + 1) > data_end) {
		return XDP_PASS;
	}
	
	// check IPv4
	if(eth->h_proto != __constant_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// ip header
	struct iphdr *iph = (struct iphdr*)(eth + 1);
	if ((void*)(iph + 1) > data_end) {
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}


	// tcp header
	struct tcphdr *tcph = (void*)iph + iph->ihl * 4;
	if ((void*)tcph + sizeof(*tcph) > data_end) {
		return XDP_PASS;
	}
	

	// // logging
	es = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!es) {
		return XDP_PASS;
	}
	
	es->src_ip = iph->saddr;
	es->src_port = tcph->source;
	es->dst_ip = iph->daddr;
	es->dst_port = tcph->dest;
	bpf_ringbuf_submit(es, 0);

	/*
	
		Client -> Load Balanccer -> Server
		Destination Mac = Server Mac
		Destination IP = Server IP

		Source Mac = LB Mac
		Source IP = LB IP
	*/
	if(iph->saddr == client_ip) {
		bpf_printk("from client\n");
		__u32 key = 0;
		struct server_config *server = bpf_map_lookup_elem(&servers, &key);
		if (!server) {
			bpf_printk("no server\n");
			return XDP_PASS;
		}

		// set server address and mac
		iph->daddr = server->ip;
		__builtin_memcpy(eth->h_dest, server->mac, ETH_ALEN);
	}

	/*
		Server -> Load Balancer -> Client

		Destination Mac = Client Mac
		Destination IP = Client IP

		Source Mac = LB Mac
		Source IP = LB IP
	*/
	else{
		// set client address and mac
		bpf_printk("from server\n");
		iph->daddr = client_ip;
		__builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
	}
	
	iph->saddr = load_balancer_ip;
	__builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);

	iph->check = iph_csum(iph);
	tcph->check = tcph_csum(tcph, iph, data_end);

	bpf_printk("Redirecting packet to new IP 0x%x from IP 0x%x", 
                bpf_ntohl(iph->daddr), 
                bpf_ntohl(iph->saddr)
            );
    bpf_printk("New Dest MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("New Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	return XDP_TX;
}
