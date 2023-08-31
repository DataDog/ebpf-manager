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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := m.Init(bytes.NewReader(Probe1)); err != nil {
		return err
	}
	defer func() {
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()
	if err := m2.Init(bytes.NewReader(Probe2)); err != nil {
		return err
	}
	defer func() {
		if err := m2.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	if err := m.Start(); err != nil {
		return err
	}
	if err := m2.Start(); err != nil {
		return err
	}

	log.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	if err := demoTailCall(); err != nil {
		log.Print(err)
	}
	return nil
}
