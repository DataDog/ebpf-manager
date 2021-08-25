#include "../../../include/all.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(struct pt_regs *ctx)
{
    bpf_printk("mkdir (vfs hook point)\n");
    return 0;
};

SEC("kprobe/utimes_common")
int kprobe_utimes_common(struct pt_regs *ctx)
{
    bpf_printk("utimes_common\n");
    return 0;
};

SEC("kretprobe/mkdirat")
int kretprobe_mkdirat(struct pt_regs *ctx)
{
    bpf_printk("mkdirat return (syscall hook point)\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
