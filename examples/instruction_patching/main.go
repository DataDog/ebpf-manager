package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe__security_socket_create",
			},
		},
	},
	InstructionPatchers: []manager.InstructionPatcherFunc{patchBPFTelemetry},
}

const BPFTelemetryPatchCall = -1

func getAllProgramSpecs(m *manager.Manager) ([]*ebpf.ProgramSpec, error) {
	var specs []*ebpf.ProgramSpec
	for _, p := range m.Probes {
		s, present, err := m.GetProgramSpec(p.ProbeIdentificationPair)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, fmt.Errorf("could not find ProgramSpec for probe %v", p.ProbeIdentificationPair)
		}

		specs = append(specs, s...)
	}

	return specs, nil
}

func patchBPFTelemetry(m *manager.Manager) error {
	specs, err := getAllProgramSpecs(m)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		if spec == nil {
			continue
		}
		iter := spec.Instructions.Iterate()
		for iter.Next() {
			ins := iter.Ins

			if !ins.IsBuiltinCall() {
				continue
			}

			if ins.Constant != BPFTelemetryPatchCall {
				continue
			}
			*ins = asm.Mov.Imm(asm.R1, int32(0xff)).WithMetadata(ins.Metadata)
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := m1.Init(bytes.NewReader(Probe)); err != nil {
		return err
	}
	defer func() {
		if err := m1.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	if err := m1.Start(); err != nil {
		return err
	}

	log.Println("=> Use 'bpftool prog dump xlated id <prog-id>' to verify that the instruction has been patched")
	log.Println("=> Enter to exit")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')

	return nil
}
