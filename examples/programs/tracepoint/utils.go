package main

import (
	"os"
	"os/exec"

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

	// trigger a fork by executing a binary
	out, err := exec.Command("date").Output()
	if err != nil {
		return err
	}
	logrus.Infof("The date is %s", out)

	// Removing a tmp directory to trigger the probes
	logrus.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
