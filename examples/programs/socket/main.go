package main

import (
	"bytes"
	_ "embed"
	"log"
	"syscall"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "sock_filter",
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
	// Create a socket pair that will be used to trigger the socket filter
	sockPair, err := newSocketPair()
	if err != nil {
		return err
	}

	// Set the socket file descriptor on which the socket filter should trigger
	m.Probes[0].SocketFD = sockPair[0]

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

	// Send a message through the socket pair to trigger the probe
	if err := trigger(sockPair); err != nil {
		log.Print(err)
	}
	return nil
}

// trigger - Send a message through the socket pair to trigger the probe
func trigger(sockPair SocketPair) error {
	log.Println("Sending a message through the socket pair to trigger the probes ...")
	_, err := syscall.Write(sockPair[1], nil)
	if err != nil {
		return err
	}
	_, err = syscall.Read(sockPair[0], nil)
	return err
}

type SocketPair [2]int

func (p SocketPair) Close() error {
	err1 := syscall.Close(p[0])
	err2 := syscall.Close(p[1])

	if err1 != nil {
		return err1
	}
	return err2
}

// newSocketPair - Create a socket pair
func newSocketPair() (SocketPair, error) {
	return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
}
