#include "all.h"
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

SEC("classifier/egress")
int egress(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on egress (TC)\n");
    return TC_ACT_OK;
};

SEC("classifier/ingress")
int ingress(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on ingress (TC)\n");
    return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
