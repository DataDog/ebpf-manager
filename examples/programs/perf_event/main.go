package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "perf_event/cpu_clock",
				EBPFFuncName: "perf_event_cpu_clock",
			},
			SampleFrequency: 1,
			PerfEventType:   unix.PERF_TYPE_SOFTWARE,
			PerfEventConfig: unix.PERF_COUNT_SW_CPU_CLOCK,
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

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("successfully started")
	logrus.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	logrus.Println("=> Cmd+C to exit")

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
