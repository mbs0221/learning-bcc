from bcc import BPF

# eBPF program
program = """
#include <uapi/linux/bpf.h>

BPF_HASH(packet_count, u32);

int packet_counter(struct __sk_buff *skb) {
    u32 src_ip = skb->src_ip;
    u64 *count = packet_count.lookup(&src_ip);
    if (count) {
        *count += 1;
    } else {
        u64 init_count = 1;
        packet_count.update(&src_ip, &init_count);
    }
    return XDP_PASS;
}
"""

# Create BPF module
bpf = BPF(text=program)

# Load eBPF program
function_packet_counter = bpf.load_func("packet_counter", BPF.XDP)

# Attach eBPF program to network interface
bpf.attach_xdp(device="eth0", function=function_packet_counter)

# Create table handler
packet_count = bpf.get_table("packet_count")

# Print packet count per source IP
for key, leaf in packet_count.items():
    print(f"Source IP: {key.value}, Packet Count: {leaf.value}")
