#ifndef _KERNEL_H__
#define _KERNEL_H__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"

#include <linux/kconfig.h>
// include asm/compiler.h to fix `error: expected string literal in 'asm'` compilation error coming from mte-kasan.h
// this was fixed in https://github.com/torvalds/linux/commit/b859ebedd1e730bbda69142fca87af4e712649a1
#ifdef CONFIG_HAVE_ARCH_COMPILER_H
#include <asm/compiler.h>
#endif

#include <linux/version.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#pragma clang diagnostic pop

#endif
