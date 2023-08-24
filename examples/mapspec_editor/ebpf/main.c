#include "all.h"
#include <uapi/linux/bpf.h>

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

char _license[] SEC("license") = "GPL";
