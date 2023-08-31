package main

import (
	"bytes"
	_ "embed"
	"log"
	"net/http"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "ingress",
			},
			IfIndex:       2, // change this to the interface index connected to the internet
			XDPAttachMode: manager.XdpAttachModeSkb,
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
	return nil
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	log.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}
