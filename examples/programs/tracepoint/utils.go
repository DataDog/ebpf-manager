package main

import (
	"log"
	"os"
	"os/exec"
)

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

	// trigger a fork by executing a binary
	out, err := exec.Command("date").Output()
	if err != nil {
		return err
	}
	log.Printf("The date is %s", out)

	// Removing a tmp directory to trigger the probes
	log.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
