#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

BPF_HASH(packet_counts, u64);

int packet_monitor(struct __sk_buff *skb) {
    u64 packet_count = 1;

    // Parse Ethernet header
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    if (!eth) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!ip) {
        return XDP_PASS;
    }

    // Update packet count
    packet_counts.increment(&ip->daddr, packet_count);

    return XDP_PASS;
}
