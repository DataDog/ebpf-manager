#include "all.h"
#include <linux/user_namespace.h>
#include <linux/dcache.h>
#include <linux/fs.h>

SEC("fentry/vfs_mkdir")
int BPF_PROG(vfs_mkdir_enter, struct user_namespace *mnt_userns, struct inode *dir,
             struct dentry *dentry, umode_t mode)
{
    bpf_printk("mkdir (vfs hook point) user_ns_ptr:%p\n", mnt_userns);
    return 0;
};

SEC("fexit/do_mkdirat")
int BPF_PROG(do_mkdirat_exit, int dfd, struct filename *fname, umode_t mode, int ret)
{
    bpf_printk("do_mkdirat return (syscall hook point) ret:%d\n", ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
