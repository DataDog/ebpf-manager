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
	if err != nil {
		return fmt.Errorf("link tracing: %w", err)
	}
	return nil
}

func (p *Probe) attachSkSKB() error {
	return link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  p.SockMap.FD(),
		Program: p.program,
		Attach:  p.programSpec.AttachType,
	})
}
