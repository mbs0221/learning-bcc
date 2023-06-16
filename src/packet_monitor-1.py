from bcc import BPF

# eBPF program
program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(packet_counts, u64);

int trace_packet(struct __sk_buff *skb) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 count = 0;
    u64 *packets = packet_counts.lookup_or_init(&pid, &count);
    (*packets)++;
    return 0;
}
"""

# Create BPF module
bpf = BPF(text=program)

# Attach eBPF program to packet events
function = bpf.load_func("trace_packet", BPF.SOCKET_FILTER)

# Attach eBPF program to network device
bpf.attach_socket(function, "eth0")

# Create table handler
packet_counts = bpf.get_table("packet_counts")

# Print packet counts
while True:
    for key, leaf in packet_counts.items():
        print(f"PID: {key.value >> 32}, Packets: {leaf.value}")
    print("----------------------")
    bpf.trace_print()
