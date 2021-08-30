package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets(probe string) io.ReaderAt {
	buf, err := Asset(probe)
	if err != nil {
		logrus.Fatal(fmt.Errorf("couldn't find asset: %w", err))
	}
	return bytes.NewReader(buf)
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	_, _ = http.Get("https://www.google.com/")
}
