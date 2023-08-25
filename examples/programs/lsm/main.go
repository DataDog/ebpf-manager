package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "lsm_security_inode_getattr",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "lsm_security_bpf",
			},
		},
	},
}

func main() {
	options := manager.Options{
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
	}

	// Initialize the manager
	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
		log.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		log.Fatal(err)
	}

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		log.Print(err)
	}

	log.Println("successfully started")
	log.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	log.Println("=> Cmd+C to exit")

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
