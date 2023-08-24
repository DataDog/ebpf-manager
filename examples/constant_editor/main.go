package main

import (
	"bytes"
	_ "embed"
	"log"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
	},
}

func main() {
	options := manager.Options{
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "my_constant",
				Value: uint64(123),
			},
		},
	}

	// Initialize the manager
	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
		log.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		log.Fatal(err)
	}

	log.Println("successfully st, checkout the value of the edited constant in /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		log.Print(err)
	}

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		log.Fatal(err)
	}
}
