from bcc import BPF

# eBPF program
program = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(file_counts, u64);

int trace_file(struct pt_regs *ctx, const char __user *filename, int flags) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 count = 0;
    u64 *files = file_counts.lookup_or_init(&pid, &count);
    (*files)++;
    return 0;
}
"""

# Create BPF module
bpf = BPF(text=program)

# Attach eBPF program to file events
bpf.attach_kprobe(event="do_sys_open", fn_name="trace_file")

# Create table handler
file_counts = bpf.get_table("file_counts")

# Print file access counts
while True:
    for key, leaf in file_counts.items():
        print(f"PID: {key.value >> 32}, Files: {leaf.value}")
    print("----------------------")
    bpf.trace_print()
