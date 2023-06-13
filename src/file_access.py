from bcc import BPF
from time import sleep

def print_file_access():
    bpf_code = """
    BPF_HASH(file_access, struct file *);

    int trace_file_access(struct pt_regs *ctx) {
        struct file *file = (struct file *)PT_REGS_RC(ctx);
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        // Filter file operations
        if (!(file->f_op && file->f_op->open && file->f_op->release))
            return 0;

        // Get the file path
        char path[MAX_PATH_LEN];
        bpf_probe_read_user_str(path, sizeof(path), file->f_path.dentry->d_name.name);

        // Record file access event
        u64 pid_tgid = bpf_get_current_pid_tgid();
        file_access.update(&file, &pid_tgid);

        return 0;
    }
    """

    bpf = BPF(text=bpf_code)
    bpf.attach_kprobe(event="do_sys_open", fn_name="trace_file_access")
    bpf.attach_kprobe(event="filp_close", fn_name="trace_file_access")
    bpf.attach_kprobe(event="vfs_read", fn_name="trace_file_access")
    bpf.attach_kprobe(event="vfs_write", fn_name="trace_file_access")

    file_access_table = bpf.get_table("file_access")

    while True:
        for k, v in file_access_table.items():
            file = k.value
            pid_tgid = v.value
            path = bpf.get_syscall_argptr(file)
            print("File Access - PID: {}, Path: {}".format(pid_tgid >> 32, path))

        sleep(1)

print_file_access()
