package manager

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
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

func TestExclude(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		Probes: []*Probe{
			{ProbeIdentificationPair: ProbeIdentificationPair{EBPFFuncName: "access_map_one"}},
		},
		Maps: []*Map{
			{Name: "map_one"},
		},
	}
	opts := Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		ExcludedMaps: []string{"map_two"},
	}

	f, err := os.Open("testdata/exclude.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	err = m.InitWithOptions(f, opts)
	if err == nil || !strings.Contains(err.Error(), "missing map map_two") {
		t.Fatalf("expected error about missing map map_two, got `%s` instead", err)
	}

	opts.ExcludedFunctions = []string{"access_map_two"}
	err = m.InitWithOptions(f, opts)
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_getTracefsRegex(t *testing.T) {
	tests := []struct {
		name          string
		Probes        []*Probe
		expectedRegex string
	}{
		{
			name: "sanity",
			Probes: []*Probe{
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "HTTP",
					},
				},
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "tcp",
					},
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(HTTP|tcp)*_([0-9]*)) .*",
		},
		{
			name: "duplications",
			Probes: []*Probe{
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "HTTP",
					},
				},
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "HTTP",
					},
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(HTTP)*_([0-9]*)) .*",
		},
		{
			name: "special character",
			Probes: []*Probe{
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "+++++",
					},
				},
				{
					ProbeIdentificationPair: ProbeIdentificationPair{
						UID: "+3.*.*",
					},
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(\\+\\+\\+\\+\\+|\\+3\\.\\*\\.\\*)*_([0-9]*)) .*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				Probes: tt.Probes,
			}
			res, err := m.getTracefsRegex()
			if err != nil {
				t.Fatal(err)
			}
			if res.String() != tt.expectedRegex {
				t.Fatalf("expected: %s, got: %s", tt.expectedRegex, res.String())
			}
		})
	}
}

func TestDumpMaps(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		Probes: []*Probe{
			{ProbeIdentificationPair: ProbeIdentificationPair{EBPFFuncName: "access_map_one"}},
		},
		Maps: []*Map{
			{Name: "map_one"},
		},
	}

	opts := Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		ExcludedFunctions: []string{"access_map_two"},
	}

	f, err := os.Open("testdata/exclude.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	err = m.InitWithOptions(f, opts)

	if err != nil {
		t.Fatal(err)
	}

	dumpContents := "mapdump"

	m.DumpHandler = func(_ *Manager, mapName string, currentMap *ebpf.Map, w io.Writer) {
		_, _ = io.WriteString(w, dumpContents)
	}

	var output bytes.Buffer
	err = m.DumpMaps(&output, "map_one")

	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, dumpContents, output.String())
}
