from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(start_time, u64);
BPF_HASH(last_seq, u64, u32);

int trace_tcp_send(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    u64 *start_ts = start_time.lookup_or_init(&pid, &timestamp);

    if (*start_ts == 0)
        *start_ts = timestamp;

    struct iphdr *iph = bpf_hdr_pointer(skb);
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

    u32 seq = ntohl(tcph->seq);
    u32 *last_seq_ptr = last_seq.lookup(&pid);

    if (last_seq_ptr) {
        u32 last_seq_num = *last_seq_ptr;
        u32 seq_diff = seq - last_seq_num;

        if (seq_diff > 0) {
            u64 duration = timestamp - *start_ts;
            u64 rate = seq_diff / (duration / 1000000000);
            bpf_trace_printk("PID: %d, Connection rate: %u bytes/s\\n", pid, rate);
        }
    }

    last_seq.update(&pid, &seq);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")

while True:
    try:
        print(b.trace_fields())
    except KeyboardInterrupt:
        break
