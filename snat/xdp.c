//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/*
    SNAT 느낌으로 진행
    Client <--> LB <--> ServerA or ServerB

    DSR
    Client <--> LB <--> Server A or ServerB 
    but response
    Server A or Server B --> Client
*/

#define LEN 2
#define MAC_LEN 6

struct backend_config {
    __u32 ip; 
    __u16 port;
    unsigned char mac[MAC_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LEN);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");

int process_packet(struct xdp_md *xdp, __u64 nh_off);

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    __u32 eth_proto; 
    __u32 nh_off;  // ethhdr size
    nh_off = sizeof(struct ethhdr); 

    // bogus packet
    if (data + nh_off > data_end) {
        return XDP_DROP; 
    }

    eth_proto = eth->h_proto;
    if (eth_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    } 

    return process_packet(ctx, nh_off);
}

/*
    client에서 왔는지 

    서버로부터 왔는지 확인한다.
*/
int process_packet(struct xdp_md *xdp, __u64 nh_off) {

    void *data = (void*)(long)xdp->data;
    void *data_end = (void*)(long)xdp->data_end;

    // 목적지 IP와 PORT가 LB_IP:9988인지 확인한다.

    // nats에 저장시 

    // TCP 플래그가 3WH의 SYN이면 backends중 하나를 골라서 nat에 저장한다. (추후)

    // RST나 FIN 플래그면 nat에서 삭제한다. 

    // 출발지 IP와 PORT가 backens[N]:9988인지 확인한다. 

    return XDP_PASS;
}