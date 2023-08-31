#include "all.h"

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on cgroup egress\n");
    return 1;
};

char _license[] SEC("license") = "GPL";
