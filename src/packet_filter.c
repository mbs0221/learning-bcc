#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>

BPF_TABLE("array", int, u64, packet_count, 1);

int packet_filter(struct __sk_buff *skb) {
    u32 source_ip = 0x01020304;  // 替换为要过滤的源IP地址
    u32 *key = NULL;
    u64 *value = NULL;
    u64 zero = 0;

    // 获取IP头部指针
    struct iphdr *ip_header = bpf_hdr_pointer(skb);

    // 检查源IP地址是否匹配
    if (ip_header->saddr == source_ip) {
        key = 0;
        value = packet_count.lookup_or_init(&key, &zero);
        (*value)++;
    }

    return XDP_PASS;
}