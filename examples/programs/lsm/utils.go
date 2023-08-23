package main

import "log"

// trigger - lookup value in eBPF map to execute a bpf syscall
func trigger() error {
	cache, _, err := m.GetMap("cache")
	if err != nil {
		return err
	}
	var key, val uint32
	if err = cache.Lookup(&key, &val); err == nil {
		log.Printf("No error detected while making a bpf syscall :(")
	} else {
		log.Printf("bpf syscall: got %v :)", err)
	}
	return nil
}
