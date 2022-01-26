#include "../../../include/all.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("lsm/bpf")
int BPF_PROG(lsm_security_bpf, int cmd) {
    bpf_printk("lsm_security_bpf cmd:%d\n", cmd);
    return -EPERM;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
