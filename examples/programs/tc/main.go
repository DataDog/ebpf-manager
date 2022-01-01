package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyUID",
				EBPFSection:  "classifier/egress",
				EBPFFuncName: "egress",
			},
			IfName:           "enp0s3", // change this to the interface connected to the internet
			NetworkDirection: manager.Egress,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "classifier/ingress",
				EBPFFuncName: "ingress",
			},
			IfName:           "enp0s3", // change this to the interface connected to the internet
			NetworkDirection: manager.Ingress,
			TCFilterChain:    2,
			TCFilterProtocol: unix.ETH_P_ARP,
			TCFilterPrio:     1000,
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Generate some network traffic to trigger the probe
	trigger()
	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
