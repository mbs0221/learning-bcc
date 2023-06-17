from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET
from struct import pack

# eBPF program
program = """
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <uapi/linux/pkt_cls.h>

BPF_TABLE("percpu_array", u32, long, packet_counts, 256);

int packet_counter(struct __sk_buff *skb) {
    u32 key = skb->ifindex;
    long *count = packet_counts.lookup(&key);
    if (count) {
        (*count)++;
    }
    return TC_ACT_OK;
}
"""

# Create BPF module
bpf = BPF(text=program)

# Attach eBPF program to network interface
bpf.attach_xdp(device="eth0", fn_name="packet_counter")

# Create table handler
packet_counts = bpf.get_table("packet_counts")

# Print packet counts for each source IP address
while True:
    for key, leaf in packet_counts.items():
        ip = pack('I', socket.ntohl(key.value))
        ip = inet_ntop(AF_INET, ip)
        print(f"Source IP: {ip}, Packets: {leaf.value}")
    print("----------------------")
    bpf.trace_print()
