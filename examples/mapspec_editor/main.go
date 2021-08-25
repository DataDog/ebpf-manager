package main

import (
	"math"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/DataDog/ebpf-manager/manager"
)

var m = &manager.Manager{}

func main() {
	options := manager.Options{
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"cache": manager.MapSpecEditor{
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
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
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
