package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "sys_enter_mkdirat",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "my_tracepoint",
			},
			TracepointCategory: "sched",
			TracepointName:     "sched_process_exec",
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

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		log.Print(err)
	}
	return nil
}

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() (err error) {
	log.Println("Generating events to trigger the probes ...")
	tmpDir, err := os.MkdirTemp("", "example")
	if err != nil {
		return fmt.Errorf("mkdirtmp: %s", err)
	}
	defer func() {
		log.Printf("removing %v", tmpDir)
		err = os.RemoveAll(tmpDir)
	}()

	// trigger a fork by executing a binary
	out, err := exec.Command("date").Output()
	if err != nil {
		return err
	}
	log.Printf("The date is %s", out)
	return nil
}
