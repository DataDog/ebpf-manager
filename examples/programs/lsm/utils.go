package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(fmt.Errorf("couldn't find asset: %w", err))
	}
	return bytes.NewReader(buf)
}

// trigger - lookup value in eBPF map to execute a bpf syscall
func trigger() error {
	cache, _, err := m.GetMap("cache")
	if err != nil {
		return err
	}
	var key, val uint32
	if err = cache.Lookup(&key, &val); err == nil {
		logrus.Warnf("No error detected while making a bpf syscall :(")
	} else {
		logrus.Printf("bpf syscall: got %v :)", err)
	}
	return nil
}
