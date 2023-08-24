#include "all.h"
#include <uapi/linux/bpf.h>
#include <linux/user_namespace.h>

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(kprobe_vfs_mkdir, struct user_namespace *mnt_userns)
{
    u64 my_constant_var = 0;
    LOAD_CONSTANT("my_constant", my_constant_var);
    bpf_printk("my_constant: %d\n", my_constant_var);
    return 0;
};

char _license[] SEC("license") = "GPL";
