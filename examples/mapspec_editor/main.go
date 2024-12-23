package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"

	"github.com/cilium/ebpf"

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
		RemoveRlimit: true,
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
	log.Println("=> Enter to continue")
	_, _ = fmt.Scanln()

	return nil
}
