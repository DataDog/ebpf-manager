package main

import (
	"bytes"
	_ "embed"

	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "sock_filter",
			},
		},
	},
}

func main() {
	// Create a socket pair that will be used to trigger the socket filter
	sockPair, err := newSocketPair()
	if err != nil {
		logrus.Fatal(err)
	}

	// Set the socket file descriptor on which the socket filter should trigger
	m.Probes[0].SocketFD = sockPair[0]

	// Initialize the manager
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Send a message through the socket pair to trigger the probe
	if err := trigger(sockPair); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
