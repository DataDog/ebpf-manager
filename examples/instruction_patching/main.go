package main

import (
	"bufio"
	"fmt"
	"os"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
)

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kprobe/security_socket_create",
				EBPFFuncName: "kprobe__security_socket_create",
			},
		},
	},
	InstructionPatcher: patchBPFTelemetry,
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
			*ins = asm.Mov.Imm(asm.R1, int32(0xff))
		}
	}

	return nil
}

func main() {
	if err := m1.Init(recoverAsset("/main.o")); err != nil {
		logrus.Fatal(err)
	}
	if err := m1.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("Use 'bpftool prog dump xlated id <prog-id>' to verify that the instruction has been patched. Press 'Enter' to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')

	cleanup()
}

func cleanup() {
	_ = m1.Stop(manager.CleanAll)
}
