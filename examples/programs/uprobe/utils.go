package main

import (
	"io"
	"log"
	"os/exec"
	"time"
)

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
