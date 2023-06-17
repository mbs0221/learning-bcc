#include <linux/sched.h>
#include <linux/mm_types.h>
#include <uapi/linux/ptrace.h>

BPF_HASH(start_time, u32, u64);

int trace_mmap(struct pt_regs *ctx, struct file *file, struct vm_area_struct *vma) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();

    start_time.update(&pid, &timestamp);

    return 0;
}

int trace_munmap(struct pt_regs *ctx, struct vm_area_struct *vma) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *timestamp_ptr = start_time.lookup(&pid);

    if (timestamp_ptr) {
        u64 start_ts = *timestamp_ptr;
        u64 end_ts = bpf_ktime_get_ns();

        u64 duration = end_ts - start_ts;

        bpf_trace_printk("PID: %d, mmap/munmap duration: %llu ns\n", pid, duration);
        start_time.delete(&pid);
    }

    return 0;
}
