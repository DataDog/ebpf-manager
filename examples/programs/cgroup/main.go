package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "egress",
			},
		},
	},
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cp, err := detectCgroupPath()
	if err != nil {
		return err
	}
	m.Probes[0].CGroupPath = cp

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

	// Generate some network traffic to trigger the probe
	trigger()
	return nil
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	log.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 is not mounted")
}
