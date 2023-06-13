#include <uapi/linux/ptrace.h>

BPF_HASH(conn_count, u32);

int count_connections(struct __sk_buff *skb) {
    u16 dst_port = bpf_ntohs(skb->dst_port);

    if (dst_port == 80 || dst_port == 443) {
        u32 zero = 0;
        u32* count = conn_count.lookup_or_init(&dst_port, &zero);
        (*count)++;
    }

    return 0;
}
