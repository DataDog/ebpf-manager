package manager

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

func (p *Probe) attachTracing() error {
	var err error
	p.progLink, err = link.AttachTracing(link.TracingOptions{
		Program:    p.program,
		AttachType: p.programSpec.AttachType,
	})

	fmt.Printf("attachTracing: progLink: %v\n", p.progLink)
	if err != nil {
		return fmt.Errorf("link tracing: %w", err)
	}
	return nil
}
