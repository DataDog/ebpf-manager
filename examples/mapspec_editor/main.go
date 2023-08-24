package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"math"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
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

	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
		return err
	}
	defer func() {
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	log.Println("successfully loaded, checkout the parameters of the map \"cache\" using bpftool")
	log.Println("=> You should see MaxEntries 1000000 instead of 10")
	_, _ = fmt.Scanln()

	return nil
}
