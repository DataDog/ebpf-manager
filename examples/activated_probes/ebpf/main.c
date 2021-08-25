#include "../../include/all.h"

SEC("kprobe/vfs_mkdir")
int vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir (vfs hook point)\n");
    return 0;
};

SEC("kprobe/utimes_common")
int utimes_common(void *ctx)
{
    bpf_printk("utimes_common\n");
    return 0;
};

SEC("kprobe/vfs_opennnnnn")
int vfs_opennnnnn(void *ctx)
{
    bpf_printk("vfs_open\n");
    return 0;
};

SEC("kprobe/exclude")
int exclude(void *ctx)
{
    bpf_printk("exclude\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
