package main

import (
	"bytes"
	_ "embed"
	"io"
	"log"
	"os/exec"
	"time"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "readline",
			},
			BinaryPath: "/usr/bin/bash",
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

	// Spawn a bash and right a command to trigger the probe
	if err := trigger(); err != nil {
		log.Print(err)
	}
	return nil
}

// trigger - Spawn a bash and execute a command to trigger the probe
func trigger() error {
	log.Println("Spawning a shell and executing `id` to trigger the probe ...")
	cmd := exec.Command("/usr/bin/bash", "-i")
	stdinPipe, _ := cmd.StdinPipe()
	go func() {
		_, _ = io.WriteString(stdinPipe, "id")
		time.Sleep(100 * time.Millisecond)
		_ = stdinPipe.Close()
	}()
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Printf("from bash: %v", string(b))
	return nil
}
