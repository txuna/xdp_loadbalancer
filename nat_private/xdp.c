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

// 10.201.0.1
int client_ip = bpf_htonl(0x0AC90001);

// de:ad:be:ef:00:01
__u8 client_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

// 10.201.0.4
int load_balancer_ip = bpf_htonl(0x0AC90004);

// de:ad:be:ef:00:04
__u8 load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};

struct server_config {
	__u32 ip;
	__u16 port;
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

///
// CALC TCP CHECKSUM

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) (((void *)PTR) + OFFSET > ((void *)END))

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

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

static __always_inline int
tcph_csum(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
	// debug
	__u32 tcp_header_len = tcph->doff * 4;
	__u32 total_len = bpf_ntohs(iph->tot_len);
	__u32 ip_header_len = (iph->ihl*4);
	__u32 payload_len = total_len - ip_header_len - tcp_header_len;

	__u32 tcp_len = tcp_header_len + payload_len; 
	
	bpf_printk("total len: %d", total_len);
	bpf_printk("ip header len: %d", ip_header_len);
	bpf_printk("tcp header size: %d", tcp_header_len);
	// bpf_printk("real header size: %d", sizeof(*tcph));
	bpf_printk("tcp payload len: %d", payload_len);

    // Clear checksum
    tcph->check = 0;

    // Pseudo header checksum calculation
    __u32 sum = 0;
    sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
    sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
    sum += bpf_htons(IPPROTO_TCP);
    // sum += bpf_htons((__u16)(data_end - (void *)tcph));
	sum += bpf_htons(tcp_len);

    // TCP header and payload checksum
    #pragma clang loop unroll_count(MAX_TCP_CHECK_WORDS)
    for (int i = 0; i <= MAX_TCP_CHECK_WORDS; i++) {
        __u16 *ptr = (__u16 *)tcph + i;
        if ((void *)ptr + 2 <= data_end){
			sum += *(__u16 *)ptr;
			continue;
		}

		// ptr + 1 == data_end 했을때는 안된 이유는?? 무조건 <=이나 >로 조건 검사해야하나 ?
		if ((void *)ptr + 1 <= data_end) {
			__u8 value = *(__u8 *)ptr;
			sum += value & bpf_htons(0xFF00);
		}

		// https://docs.kernel.org/bpf/verifier.html?utm_source=chatgpt.com#direct-packet-access
		// 해당 조건이 옳아도 bpf 검증기에서 아래 조건과 ptr 접근이 관련이 없어서 검증되지않았다고 판단하는건가? 커널 소스 분석좀 해야겠다.
		// if ((void*)ptr + 1 == data_end){
		// 	// *ptr blah blah
		// 	__u8 value = *(__u8 *)ptr;
		// 	sum += value & bpf_htons(0xFF00);
		// }

        break;
    }

	sum = ~csum_reduce_helper(sum);
	tcph->check = (unsigned short)sum;
	return 0;
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
	// tcph->check = tcph_csum(tcph, iph, data_end);
	int ret; 
	ret = tcph_csum(tcph, iph, data_end);
	if(ret == -1) {
		return XDP_DROP;
	}

	bpf_printk("Redirecting packet to new IP 0x%x from IP 0x%x", 
                bpf_ntohl(iph->daddr), 
                bpf_ntohl(iph->saddr)
            );
    bpf_printk("New Dest MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("New Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	return XDP_TX;
}
