from bcc import BPF

# eBPF program
program = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(file_reads, u64);
BPF_HASH(file_writes, u64);

int trace_read_entry(struct pt_regs *ctx, struct file *file) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 count = 0;
    u64 *reads = file_reads.lookup_or_init(&pid, &count);
    (*reads)++;
    return 0;
}

int trace_write_entry(struct pt_regs *ctx, struct file *file) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 count = 0;
    u64 *writes = file_writes.lookup_or_init(&pid, &count);
    (*writes)++;
    return 0;
}
"""

# Create BPF module
bpf = BPF(text=program)

# Attach eBPF program to file read/write events
bpf.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
bpf.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")

# Create table handlers
file_reads = bpf.get_table("file_reads")
file_writes = bpf.get_table("file_writes")

# Print file read/write counts
while True:
    print("File Read Counts:")
    for key, leaf in file_reads.items():
        print(f"PID: {key.value >> 32}, Count: {leaf.value}")
    print("File Write Counts:")
    for key, leaf in file_writes.items():
        print(f"PID: {key.value >> 32}, Count: {leaf.value}")
    print("----------------------")
    bpf.kprobe_poll()
