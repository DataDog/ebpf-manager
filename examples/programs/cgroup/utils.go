package main

import (
	"log"
	"net/http"
)

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	log.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}
