package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
)

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	log.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	log.Printf("creating %v", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Removing a tmp directory to trigger the probes
	log.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
