package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/prog1.o
var Probe1 []byte

//go:embed ebpf/bin/prog2.o
var Probe2 []byte

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kretprobe_vfs_mkdir",
			},
		},
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_vfs_mkdir",
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
	if err := m1.Init(bytes.NewReader(Probe1)); err != nil {
		return err
	}
	defer func() {
		if err := m1.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
		if err := m2.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()
	if err := m1.Start(); err != nil {
		return err
	}
	log.Println("Head over to /sys/kernel/debug/tracing/trace_pipe to see the eBPF programs in action")

	// Start demos
	if err := demoMapEditor(); err != nil {
		return err
	}
	if err := demoMapRouter(); err != nil {
		return err
	}
	return nil
}

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	log.Println("Generating events to trigger the probes ...")
	tmpDir, err := os.MkdirTemp("", "example")
	if err != nil {
		return fmt.Errorf("mkdirtmp: %s", err)
	}
	log.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}

// dumpSharedMap - Dumps the content of the provided map at the provided key
func dumpSharedMap(sharedMap *ebpf.Map) error {
	var key, val uint32
	entries := sharedMap.Iterate()
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		log.Printf("%v contains %v at key %v", sharedMap, val, key)
	}
	return entries.Err()
}
