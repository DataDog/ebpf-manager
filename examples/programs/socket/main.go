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
				EBPFFuncName: "sock_filter",
			},
		},
	},
}

func main() {
	// Create a socket pair that will be used to trigger the socket filter
	sockPair, err := newSocketPair()
	if err != nil {
		log.Fatal(err)
	}

	// Set the socket file descriptor on which the socket filter should trigger
	m.Probes[0].SocketFD = sockPair[0]

	// Initialize the manager
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		log.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		log.Fatal(err)
	}

	log.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Send a message through the socket pair to trigger the probe
	if err := trigger(sockPair); err != nil {
		log.Print(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		log.Fatal(err)
	}
}
