package main

import (
	"bytes"
	_ "embed"
	"math"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe.o
var Probe []byte

var m = &manager.Manager{}

func main() {
	options := manager.Options{
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"cache": {
				Type:       ebpf.LRUHash,
				MaxEntries: 1000000,
				EditorFlag: manager.EditMaxEntries | manager.EditType,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	// Initialize the manager
	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully loaded, checkout the parameters of the map \"cache\" using bpftool")
	logrus.Println("=> You should see MaxEntries 1000000 instead of 10")

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
