from bcc import BPF

def print_syscall_stats():
    bpf_code = """
    #include <linux/ptrace.h>
    #include <linux/sched.h>

    struct sys_execve_args {
        const char __user *filename;
        const char __user *const __user *argv;
        const char __user *const __user *envp;
    };

    BPF_HASH(syscalls, u32);
    BPF_HASH(args, u64, struct sys_execve_args);

    int trace_sys_enter(struct pt_regs *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 syscall_id = PT_REGS_PARM1(ctx);

        syscalls.increment(syscall_id);

        // Store execve arguments for later analysis
        if (syscall_id == __NR_execve) {
            struct sys_execve_args arguments = {
                .filename = (const char __user *)PT_REGS_PARM2(ctx),
                .argv = (const char __user *const __user *)PT_REGS_PARM3(ctx),
                .envp = (const char __user *const __user *)PT_REGS_PARM4(ctx)
            };
            args.update(&pid, &arguments);
        }

        return 0;
    }
    """

    b = BPF(text=bpf_code)
    b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_sys_enter")

    print("Tracing syscalls...")

    try:
        while True:
            for (syscall, count) in b.get_table("syscalls").items():
                print("Syscall {}: Count = {}".format(syscall, count.value))

            for (pid, args) in b.get_table("args").items():
                print("PID {}: Execve Arguments = filename={}, argv={}, envp={}".format(
                    pid, args.filename, args.argv, args.envp))

            b.get_table("syscalls").clear()
            b.get_table("args").clear()
            b.trace_print()

    except KeyboardInterrupt:
        pass

print_syscall_stats()
