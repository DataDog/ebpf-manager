package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	logrus.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	logrus.Printf("creating %v", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Removing a tmp directory to trigger the probes
	logrus.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
