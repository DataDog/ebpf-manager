package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"net/http"

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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		return err
	}
	defer func() {
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()
	if err := m.Start(); err != nil {
		return err
	}

	log.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Generate some network traffic to trigger the probe
	trigger()
	_, _ = fmt.Scanln()

	return nil
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	log.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}
