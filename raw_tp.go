package manager

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// attachRawTracepoint - Attaches the probe to its raw_tracepoint
func (p *Probe) attachRawTracepoint() error {
	var err error
	p.progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    p.TracepointName,
		Program: p.program,
	})
	if err != nil {
		return fmt.Errorf("link raw tracepoint: %w", err)
	}
	return nil
}
