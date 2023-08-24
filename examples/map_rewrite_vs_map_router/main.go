package main

import (
	"bytes"
	_ "embed"
	"log"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/prog1.o
var Probe1 []byte

//go:embed ebpf/bin/prog2.o
var Probe2 []byte

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kretprobe_vfs_mkdir",
			},
		},
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
	},
}

func main() {
	// Initialize & start m1
	if err := m1.Init(bytes.NewReader(Probe1)); err != nil {
		log.Fatal(err)
	}
	if err := m1.Start(); err != nil {
		log.Fatal(err)
	}
	log.Println("Head over to /sys/kernel/debug/tracing/trace_pipe to see the eBPF programs in action")

	// Start demos
	if err := demoMapEditor(); err != nil {
		log.Print(err)
		cleanup()
		return
	}
	if err := demoMapRouter(); err != nil {
		log.Print(err)
		cleanup()
		return
	}

	// Close the managers
	if err := m1.Stop(manager.CleanAll); err != nil {
		log.Fatal(err)
	}
	if err := m2.Stop(manager.CleanInternal); err != nil {
		log.Fatal(err)
	}
}

func cleanup() {
	_ = m1.Stop(manager.CleanAll)
	_ = m2.Stop(manager.CleanInternal)
}
