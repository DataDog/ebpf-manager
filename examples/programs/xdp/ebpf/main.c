#include "all.h"
#include <uapi/linux/bpf.h>

SEC("xdp/ingress")
int ingress(struct __sk_buff *skb)
{
    bpf_printk("new packet captured (XDP)\n");
    return XDP_PASS;
};

char _license[] SEC("license") = "GPL";
