package main

import (
	"bytes"
	_ "embed"

	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe1.o
var Probe1 []byte

//go:embed ebpf/bin/probe2.o
var Probe2 []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "one",
			},
			IfName:           "lo", // change this to the interface index connected to the internet
			NetworkDirection: manager.Egress,
		},
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{},
}

func main() {
	// Initialize the manager
	if err := m.Init(bytes.NewReader(Probe1)); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Init(bytes.NewReader(Probe2)); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	if err := demoTailCall(); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
