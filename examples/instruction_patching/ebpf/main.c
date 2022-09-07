#include "../../include/all.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;


static void *(*bpf_patch)(unsigned long...) = (void *)-1;

SEC("kprobe/security_socket_create")
int kprobe__security_socket_create(struct pt_regs* ctx) {
    bpf_patch();
    return 1;
}
