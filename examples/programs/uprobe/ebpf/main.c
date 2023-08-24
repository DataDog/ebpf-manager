#include "all.h"

SEC("uprobe/readline")
int readline(void *ctx)
{
    bpf_printk("new bash command detected\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
