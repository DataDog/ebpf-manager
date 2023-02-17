#include "all.h"
#include <uapi/linux/bpf.h>
#include <uapi/linux/errno.h>

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("lsm/inode_getattr")
int BPF_PROG(lsm_security_inode_getattr, struct path *pp) {
    char p[128] = {};
    int ret = bpf_d_path(pp, &p[0], 128);
    bpf_printk("ret:%d path:%s\n", ret, p);
    return 0;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_security_bpf, int cmd) {
    bpf_printk("lsm_security_bpf cmd:%d\n", cmd);
    return -EPERM;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
