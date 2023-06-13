from bcc import BPF
from time import sleep

def print_file_access():
    bpf_code = """
    BPF_HASH(files, struct file *);

    int trace_file_open(struct pt_regs *ctx) {
        struct file *file = (struct file *)PT_REGS_PARM1(ctx);

        // Record file open event
        u64 pid_tgid = bpf_get_current_pid_tgid();
        files.update(&file, &pid_tgid);

        return 0;
    }

    int trace_file_read(struct pt_regs *ctx) {
        struct file *file = (struct file *)PT_REGS_PARM1(ctx);

        // Perform file read analysis
        // ...

        return 0;
    }

    int trace_file_write(struct pt_regs *ctx) {
        struct file *file = (struct file *)PT_REGS_PARM1(ctx);

        // Perform file write analysis
        // ...

        return 0;
    }
    """

    bpf = BPF(text=bpf_code)
    bpf.attach_kprobe(event="do_sys_open", fn_name="trace_file_open")
    bpf.attach_kprobe(event="vfs_read", fn_name="trace_file_read")
    bpf.attach_kprobe(event="vfs_write", fn_name="trace_file_write")

    while True:
        print("File Access:")
        for k, v in bpf["files"].items():
            file = k.value
            pid_tgid = v.value
            file_path = bpf.sym(file.f_path.dentry.d_name.name)
            print("PID: {}, File: {}".format(pid_tgid >> 32, file_path))
            print()

        sleep(1)

print_file_access()
