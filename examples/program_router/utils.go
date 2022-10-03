package main

import (
	"net/http"
)

// trigger1 - Generate some network traffic to trigger the probe
func trigger1() {
	_, _ = http.Get("https://www.google.com/")
}

// trigger2 - Generate some network traffic to trigger the probe
func trigger2() {
	_, _ = http.Get("https://www.google.fr/")
}
