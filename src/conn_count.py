from bcc import BPF
from time import sleep

def print_conn_count():
    bpf_code = """
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
    """

    bpf = BPF(text=bpf_code)
    count_table = bpf.get_table("conn_count")

    while True:
        for k, v in count_table.items():
            print("Port: {}, Count: {}".format(k.value, v.value))

        sleep(1)

print_conn_count()
