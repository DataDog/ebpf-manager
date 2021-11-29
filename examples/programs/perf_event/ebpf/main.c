#include "../../../include/all.h"

SEC("perf_event/cpu_clock")
int perf_event_cpu_clock(struct bpf_perf_event_data *ctx)
{
    bpf_printk("pid %d is currently running on cpu %d (sample_period: %d)\n", bpf_get_current_pid_tgid() >> 32, bpf_get_smp_processor_id(), ctx->sample_period);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
