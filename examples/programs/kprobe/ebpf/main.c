#include "all.h"
#include <uapi/linux/bpf.h>
#include <linux/user_namespace.h>

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(kprobe_vfs_mkdir, struct user_namespace *mnt_userns)
{
    bpf_printk("mkdir (vfs hook point) user_ns_ptr:%p\n", mnt_userns);
    return 0;
};

SEC("kretprobe/utimes_common")
int kretprobe_utimes_common(struct pt_regs *ctx)
{
    bpf_printk("utimes_common return\n");
    return 0;
};

SEC("kretprobe/mkdirat")
int BPF_KRETPROBE(kretprobe_mkdirat, int ret)
{
    bpf_printk("mkdirat return (syscall hook point) ret:%d\n", ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
