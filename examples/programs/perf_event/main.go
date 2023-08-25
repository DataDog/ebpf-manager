package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "perf_event_cpu_clock",
			},
			SampleFrequency: 1,
			PerfEventType:   unix.PERF_TYPE_SOFTWARE,
			PerfEventConfig: unix.PERF_COUNT_SW_CPU_CLOCK,
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

	log.Println("successfully started")
	log.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	log.Println("=> Enter to exit")
	_, _ = fmt.Scanln()

	return nil
}
