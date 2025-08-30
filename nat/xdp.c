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

#define SERVER_NUM 3 // 0 is loadbalancer
#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent

char _license[] SEC("license") = "GPL";

struct server_config {
	__u32 ip;
	u8 	mac[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SERVER_NUM);
	__type(key, __u32);
	__type(value, struct server_config);
} servers SEC(".maps");

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
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper((__u64)csum);
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

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;

	bpf_printk("xdp loadbalancer received packet!"); 

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

	bpf_printk("Received Source IP: 0x%x\n", bpf_ntohl(iph->saddr));
	bpf_printk("Received Destination IP: 0x%x\n", bpf_ntohl(iph->daddr));
	bpf_printk("Received Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("Received Destination MAC: %x:%x:%x:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	
	return XDP_PASS;
}
