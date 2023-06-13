#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <uapi/linux/ptrace.h>

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
