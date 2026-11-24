#include "common.h"

char __license[] __section("license") = "MIT";

struct map program_bypassed __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint32_t),
	.max_entries = 1,
};

#define TC_ACT_SHOT 2

#define CHECK_BPF_PROGRAM_BYPASSED() \
	unsigned long bypass_program; \
	asm("%0 = bypass_program ll" : "=r"(bypass_program) :: "memory");

__section("classifier/bypass") int classifier_bypass() {
	CHECK_BPF_PROGRAM_BYPASSED()
	return TC_ACT_SHOT;
}

__section("kprobe/bypass") int kprobe_bypass() {
	CHECK_BPF_PROGRAM_BYPASSED()
	return 0;
}
