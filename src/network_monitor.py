from bcc import BPF
from time import sleep

def print_network_connections():
    bpf_code = """
    BPF_HASH(connections, struct sock *);

    int trace_connect(struct pt_regs *ctx) {
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        u32 daddr = sk->__sk_common.skc_daddr;

        // Record connection establishment event
        u64 pid_tgid = bpf_get_current_pid_tgid();
        connections.update(&sk, &pid_tgid);

        return 0;
    }

    int trace_tcp_close(struct pt_regs *ctx) {
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

        // Record connection close event
        u64 pid_tgid = bpf_get_current_pid_tgid();
        connections.delete(&sk);

        return 0;
    }

    int trace_tcp_send(struct pt_regs *ctx) {
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        u32 daddr = sk->__sk_common.skc_daddr;

        // Perform data transmission analysis
        // ...

        return 0;
    }
    """

    bpf = BPF(text=bpf_code)
    bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
    bpf.attach_kprobe(event="tcp_close", fn_name="trace_tcp_close")
    bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")

    while True:
        print("Network Connections:")
        for k, v in bpf["connections"].items():
            sk = k.value
            pid_tgid = v.value
            local_ip = bpf.ntohl(sk.__sk_common.skc_rcv_saddr)
            local_port = sk.__sk_common.skc_num
            remote_ip = bpf.ntohl(sk.__sk_common.skc_daddr)
            remote_port = sk.__sk_common.skc_dport
            print("PID: {}, Local: {}:{}".format(pid_tgid >> 32, local_ip, local_port))
            print("     Remote: {}:{}".format(remote_ip, remote_port))
            print()

        sleep(1)

print_network_connections()
