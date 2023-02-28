package main

import (
	"bytes"
	_ "embed"

	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "sys_enter_mkdirat",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "my_tracepoint",
			},
			TracepointCategory: "sched",
			TracepointName:     "sched_process_exec",
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
