package manager

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

func multiTestSpec() (*ebpf.CollectionSpec, []TailCallRoute) {
	root := func() *ebpf.ProgramSpec {
		return &ebpf.ProgramSpec{Type: ebpf.Kprobe, SectionName: "uprobe/test", License: "GPL", Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0).WithReference(bypassOptInReference),
			asm.LoadMapPtr(asm.R2, 0).WithReference("routes"),
			asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return(),
		}}
	}
	return &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"tls": root(), "legacy": root(),
			"decoder": {Type: ebpf.Kprobe, SectionName: "uprobe/decoder", License: "GPL", Instructions: asm.Instructions{
				asm.StoreImm(asm.RFP, -4, 0, asm.Word),
				asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
				asm.LoadMapPtr(asm.R1, 0).WithReference("counts"), asm.FnMapLookupElem.Call(),
				asm.JEq.Imm(asm.R0, 0, "exit"),
				asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
				asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return(),
			}},
		},
		Maps: map[string]*ebpf.MapSpec{
			"routes":      {Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			bypassMapName: {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			"counts":      {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		},
	}, []TailCallRoute{{ProgArrayName: "routes", ProbeIdentificationPair: ProbeIdentificationPair{EBPFFuncName: "decoder"}}}
}

func TestPrepareUprobeMulti(t *testing.T) {
	original, routes := multiTestSpec()
	prepared, privateRoutes, err := prepareUprobeMulti(original, []string{"tls"}, routes)
	if err != nil {
		t.Fatal(err)
	}
	if original.Programs["tls"].AttachType != 0 || prepared.Programs["tls"].AttachType != ebpf.AttachTraceUprobeMulti {
		t.Fatal("only the selected copy should change attachment type")
	}
	if prepared.Programs["legacy"].AttachType != 0 || prepared.Programs["decoder"].AttachType != 0 {
		t.Fatal("legacy caller and decoder must remain compatible")
	}
	if prepared.Programs["decoder"+uprobeMultiSuffix].AttachType != ebpf.AttachTraceUprobeMulti {
		t.Fatal("missing compatible decoder")
	}
	if prepared.Programs["tls"].Instructions[1].Reference() != "routes"+uprobeMultiSuffix || prepared.Programs["legacy"].Instructions[1].Reference() != "routes" {
		t.Fatal("routing arrays must be isolated")
	}
	if !reflect.DeepEqual(prepared.Programs["decoder"].Instructions, prepared.Programs["decoder"+uprobeMultiSuffix].Instructions) {
		t.Fatal("preserve patched decoder instructions and shared data-map references")
	}
	if len(privateRoutes) != 1 || privateRoutes[0].ProgArrayName != "routes"+uprobeMultiSuffix || privateRoutes[0].ProbeIdentificationPair.EBPFFuncName != "decoder"+uprobeMultiSuffix {
		t.Fatalf("wrong private routes: %+v", privateRoutes)
	}
	for _, missing := range []string{"absent", "legacy" + uprobeMultiSuffix} {
		if _, _, err := prepareUprobeMulti(original, []string{missing}, routes); err == nil {
			t.Fatal("missing roots must fail")
		}
	}
	routes[0].Program = &ebpf.Program{}
	if _, _, err := prepareUprobeMulti(original, []string{"tls"}, routes); err == nil {
		t.Fatal("external decoder programs cannot be converted")
	}
}

func TestMultiUprobeOffsetsCopy(t *testing.T) {
	p := &Probe{UprobeOffsets: []uint64{10, 20}, UprobeOffset: 42, UprobeAttachMethod: AttachWithProbeEvents}
	copy := p.Copy()
	copy.UprobeOffsets[0] = 99
	if p.UprobeOffsets[0] != 10 || copy.UprobeOffset != 42 || copy.UprobeAttachMethod != p.UprobeAttachMethod {
		t.Fatal("Copy must retain attachment options without sharing the offsets slice")
	}
}

//go:noinline
func multiUprobeTestTarget(v int) int { return v + 1 }

//go:noinline
func multiUprobeTestOtherTarget(v int) int { return v + 2 }

// TestMultiUprobeIntegration uses only this process's executable. The opt-in
// avoids attaching probes on an ordinary developer test run. Run privileged.
func TestMultiUprobeIntegration(t *testing.T) {
	if os.Getenv("EBPF_MANAGER_UPROBE_MULTI_TEST") != "1" {
		t.Skip("set EBPF_MANAGER_UPROBE_MULTI_TEST=1 in an isolated privileged environment")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := findSymbolOffsets(executable, regexp.MustCompile(`multiUprobeTest(Target|OtherTarget)$`))
	if err != nil || len(symbols) != 2 {
		t.Fatalf("find target: %v, %+v", err, symbols)
	}
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "multi"}[multi], func(t *testing.T) {
			spec, routes := multiTestSpec()
			m := &Manager{collectionSpec: spec, state: elfLoaded}
			opts := Options{TailCallRouter: routes, BypassEnabled: true}
			if multi {
				opts.UprobeMultiPrograms = []string{"tls"}
			}
			if err := m.InitWithOptions(nil, opts); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Stop(CleanAll) })
			enabled, fallback := m.UprobeMultiStatus()
			if enabled != multi || fallback != nil {
				t.Fatalf("wrong backend: enabled=%v fallback=%v", enabled, fallback)
			}
			if err := m.UpdateTailCallRoutes(routes...); err != nil {
				t.Fatal(err)
			}
			// Avoid Start's global stale-tracefs cleanup: these tests attach
			// only explicit dynamic hooks. Exercise real manager pause/resume.
			m.state = running
			var ids []ProbeIdentificationPair
			for _, name := range []string{"tls", "legacy"} {
				groups := [][]uint64{{symbols[0].Value}, {symbols[1].Value}}
				if multi && name == "tls" {
					groups = [][]uint64{{symbols[0].Value, symbols[1].Value}}
				}
				for i, offsets := range groups {
					id := ProbeIdentificationPair{EBPFFuncName: name, UID: fmt.Sprint("target-", i)}
					probe := &Probe{ProbeIdentificationPair: id, BinaryPath: executable, PerfEventPID: os.Getpid(), UprobeOffset: offsets[0]}
					if multi && name == "tls" {
						probe.UprobeOffsets = offsets
					}
					if err := m.AddHook("", probe); err != nil {
						t.Fatal(err)
					}
					ids = append(ids, id)
				}
			}

			if got := multiUprobeTestTarget(41); got != 42 {
				t.Fatal(got)
			}
			if got := multiUprobeTestOtherTarget(40); got != 42 {
				t.Fatal(got)
			}
			var count uint64
			if err := m.collection.Maps["counts"].Lookup(uint32(0), &count); err != nil || count != 4 {
				t.Fatalf("both decoder variants must update the same data map: count=%d err=%v", count, err)
			}
			if err := m.Pause(); err != nil {
				t.Fatal(err)
			}
			_ = multiUprobeTestTarget(1)
			var paused uint64
			if err := m.collection.Maps["counts"].Lookup(uint32(0), &paused); err != nil || paused != count {
				t.Fatalf("paused probes still execute: %d, %v", paused, err)
			}
			if err := m.Resume(); err != nil {
				t.Fatal(err)
			}
			_ = multiUprobeTestTarget(1)
			count += 2
			var resumed uint64
			if err := m.collection.Maps["counts"].Lookup(uint32(0), &resumed); err != nil || resumed != count {
				t.Fatalf("resume lost monitoring: %d, %v", resumed, err)
			}
			for _, id := range ids {
				if err := m.DetachHook(id); err != nil {
					t.Fatal(err)
				}
			}

			_ = multiUprobeTestTarget(42)
			var after uint64
			if err := m.collection.Maps["counts"].Lookup(uint32(0), &after); err != nil || after != count {
				t.Fatalf("detached groups still execute: %d, %v", after, err)
			}
		})
	}
}

func TestMultiUprobeLoadFallback(t *testing.T) {
	if os.Getenv("EBPF_MANAGER_UPROBE_MULTI_TEST") != "1" {
		t.Skip("privileged collection loading")
	}
	spec, routes := multiTestSpec()
	m := &Manager{collectionSpec: spec, state: elfLoaded}
	// An invalid optional root must not prevent loading the valid legacy graph.
	if err := m.InitWithOptions(nil, Options{TailCallRouter: routes, UprobeMultiPrograms: []string{"absent"}}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop(CleanAll) }()
	if enabled, err := m.UprobeMultiStatus(); enabled || err == nil || errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("expected a preparation failure and working legacy collection: %v %v", enabled, err)
	}
}
