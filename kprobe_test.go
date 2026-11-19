//go:build linux

package manager

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestAttachKprobeMulti(t *testing.T) {
	if err := features.HaveBPFLinkKprobeMulti(); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("multi-kprobe unsupported: %v", err)
		}
		t.Fatalf("detect multi-kprobe support: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}
	symbol, err := GetSyscallFnName("getpid")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		ret     bool
		unknown bool
	}{
		{name: "entry"}, {name: "return", ret: true},
		{name: "unknown_entry", unknown: true}, {name: "unknown_return", ret: true, unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &ebpf.ProgramSpec{
				Name: "test_kp_multi", Type: ebpf.Kprobe, AttachType: ebpf.AttachTraceKprobeMulti,
				License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			}
			prog, err := ebpf.NewProgram(spec)
			if err != nil {
				t.Fatalf("load program: %v", err)
			}
			t.Cleanup(func() {
				if err := prog.Close(); err != nil {
					t.Error(err)
				}
			})
			p := &Probe{HookFuncName: symbol, program: prog, programSpec: spec, isReturnProbe: tc.ret, Enabled: true}
			if !p.SupportsKprobeMulti() {
				t.Fatal("missing capability marker")
			}
			if tc.unknown {
				p.HookFuncName = "ebpf_manager_nonexistent_kprobe_multi_symbol"
			}
			err = p.attachKprobe()
			if tc.unknown {
				if errors.Is(err, os.ErrPermission) {
					t.Fatalf("unknown-symbol attachment permission error: %v", err)
				}
				if p.progLink != nil {
					_ = p.progLink.Close()
					t.Fatal("failed attachment retained a link")
				}
				if err == nil {
					t.Fatal("unknown symbol attachment succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("attach: %v", err)
			}
			p.state = running
			t.Cleanup(func() {
				if err := p.Detach(); err != nil {
					t.Error(err)
				}
			})
			l, ok := p.progLink.(link.Link)
			if !ok {
				t.Fatalf("expected BPF link, got %T", p.progLink)
			}
			info, err := l.Info()
			if err != nil {
				t.Fatal(err)
			}
			multi := info.KprobeMulti()
			if multi == nil {
				t.Fatal("missing multi-kprobe metadata")
			}
			if multi.Count != 1 {
				t.Errorf("target count = %d, want 1", multi.Count)
			}
			var flags uint32
			if tc.ret {
				flags = unix.BPF_F_KPROBE_MULTI_RETURN
			}
			if multi.Flags != flags {
				t.Errorf("flags = %#x, want %#x", multi.Flags, flags)
			}
			if err := p.Detach(); err != nil {
				t.Fatalf("detach: %v", err)
			}
			if _, err := l.Info(); err == nil {
				t.Fatal("link still open after Probe.Detach")
			}
		})
	}
}
