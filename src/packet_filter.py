from bcc import BPF, Socket
import ctypes

# 定义eBPF程序
bpf_program = """
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
"""

# 加载eBPF程序
bpf = BPF(text=bpf_program)

# 创建Raw Socket对象，捕获网络数据包
socket = Socket(0, 0)

# 获取BPF数组
packet_count = bpf.get_table("packet_count")

# 读取和打印过滤到的数据包数量
def print_packet_count():
    key = ctypes.c_int(0)
    value = packet_count[key]
    print("Filtered packets:", value.value)
    packet_count.clear()

# 循环读取和打印数据包数量
while True:
    try:
        # 捕获网络数据包
        packet = socket.recvfrom(65535)
        # 发送数据包到eBPF程序进行过滤
        bpf["packet_filter"].trace(packet)
        # 每隔1秒打印过滤到的数据包数量
        print_packet_count()
    except KeyboardInterrupt:
        break
