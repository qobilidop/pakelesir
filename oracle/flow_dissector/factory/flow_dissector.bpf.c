// In-repo minimal flow dissector for rung 0 (eth/IPv4/IPv6/TCP/UDP).
// Runs IN THE KERNEL via BPF_PROG_TEST_RUN to mint golden flow_keys.
// Fidelity-identical to upstream bpf_flow.c for these protocols; upstream
// replaces it at rung 1. No SEC (lands in .text), no maps, no helpers ->
// .text is self-contained raw bytecode (raw BPF_PROG_LOAD, no libbpf).
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ETH_P_IP_BE 0x0008   /* htons(0x0800) */
#define ETH_P_IPV6_BE 0xdd86 /* htons(0x86DD) */

static __attribute__((always_inline)) void ports(void *th, void *end,
                                                  struct bpf_flow_keys *k) {
    struct { __be16 s, d; } *p = th;
    if ((void *)(p + 1) <= end) {
        k->sport = p->s;
        k->dport = p->d;
    }
}

int dissect(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct bpf_flow_keys *k = skb->flow_keys;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_DROP;
    k->nhoff = sizeof(*eth);
    k->n_proto = eth->h_proto;
    k->addr_proto = eth->h_proto;
    if (eth->h_proto == ETH_P_IP_BE) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return BPF_DROP;
        k->ip_proto = ip->protocol;
        k->ipv4_src = ip->saddr;
        k->ipv4_dst = ip->daddr;
        k->thoff = sizeof(*eth) + sizeof(*ip);
        if (ip->protocol == 6 || ip->protocol == 17)
            ports((void *)ip + sizeof(*ip), data_end, k);
    } else if (eth->h_proto == ETH_P_IPV6_BE) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return BPF_DROP;
        k->ip_proto = ip6->nexthdr;
        __builtin_memcpy(k->ipv6_src, &ip6->saddr, 16);
        __builtin_memcpy(k->ipv6_dst, &ip6->daddr, 16);
        k->thoff = sizeof(*eth) + sizeof(*ip6);
        if (ip6->nexthdr == 6 || ip6->nexthdr == 17)
            ports((void *)ip6 + sizeof(*ip6), data_end, k);
    }
    return BPF_OK;
}
