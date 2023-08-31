#include "all.h"

SEC("socket/sock_filter")
int sock_filter(void *ctx)
{
    bpf_printk("new packet received\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
