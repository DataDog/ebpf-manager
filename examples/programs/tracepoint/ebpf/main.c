#include "../../../include/all.h"

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int sys_enter_mkdirat(void *ctx)
{
    bpf_printk("mkdirat enter (tracepoint)\n");
    return 0;
};

SEC("tracepoint/my_tracepoint")
int my_tracepoint(void *ctx)
{
    bpf_printk("my_tracepoint (tracepoint)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
