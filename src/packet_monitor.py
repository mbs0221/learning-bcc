from bcc import BPF

def print_packet_counts():
    b = BPF(src_file="packet_monitor.o")
    fn = b.load_func("packet_monitor", BPF.XDP)

    b.attach_xdp(device="eth0", fn=fn)

    packet_counts = b.get_table("packet_counts")

    try:
        while True:
            for (ip, count) in packet_counts.items():
                print("IP: {}, Count: {}".format(ip, count.value))

            packet_counts.clear()
            b.perf_buffer_poll()

    except KeyboardInterrupt:
        pass

print_packet_counts()
