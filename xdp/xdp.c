//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES); 
    __type(key, __u32);
    __type(value, __u32);
} xdp_stats_map SEC(".maps");

static __always_inline int parse_ip_src_addr(struct xdp_mp *ctx, __u32 *ip_src_addr) {
    void *data_end = (void*)(long)ctx->data_end;
    void data = (void*)(long)ctx->data; 

    struct ethhdr *eth = data;
}