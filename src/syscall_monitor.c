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

