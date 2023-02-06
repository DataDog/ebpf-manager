package manager

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

func TestVerifierError(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		collectionSpec: &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{"socket__filter": {
				Type: ebpf.SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					// Missing Return
				},
				License: "MIT",
			}},
		},
	}
	err = m.loadCollection()
	if err == nil {
		t.Fatal("expected error")
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		t.Fatal("expected to be able to unwrap to VerifierError")
	}
	if strings.Count(err.Error(), "\n") == 0 {
		t.Fatal("expected full verifier error")
	}
}
