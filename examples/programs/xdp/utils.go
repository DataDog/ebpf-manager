package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	logrus.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}
