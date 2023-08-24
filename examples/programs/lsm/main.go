package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	options := manager.Options{
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
	}
	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
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

	if err := trigger(); err != nil {
		log.Print(err)
	}

	log.Println("successfully started")
	log.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	log.Println("=> Enter to exit")
	_, _ = fmt.Scanln()
	return nil
}

// trigger - lookup value in eBPF map to execute a bpf syscall
func trigger() error {
	cache, _, err := m.GetMap("cache")
	if err != nil {
		return err
	}
	var key, val uint32
	if err = cache.Lookup(&key, &val); err == nil {
		log.Printf("No error detected while making a bpf syscall :(")
	} else {
		log.Printf("bpf syscall: got %v :)", err)
	}
	return nil
}
