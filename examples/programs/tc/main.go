package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyUID",
				EBPFFuncName: "egress",
			},
			IfName:           "lo", // change this to the interface connected to the internet
			NetworkDirection: manager.Egress,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "ingress",
			},
			IfName:           "lo", // change this to the interface connected to the internet
			NetworkDirection: manager.Ingress,
			TCFilterProtocol: unix.ETH_P_ARP,
			TCFilterPrio:     1000,
			TCFilterHandle:   netlink.MakeHandle(0, 2),
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		log.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		log.Fatal(err)
	}

	log.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Generate some network traffic to trigger the probe
	trigger()
	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		log.Fatal(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println()
}
