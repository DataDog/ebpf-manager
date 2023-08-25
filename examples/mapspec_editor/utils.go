package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println()
}
