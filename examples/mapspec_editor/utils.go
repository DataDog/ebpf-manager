package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"

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

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
