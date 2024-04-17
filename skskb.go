package manager

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (p *Probe) attachSkSKB() error {
	return link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  p.SockMapFD,
		Program: p.program,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
}

func (p *Probe) detachSkSKB() error {
	return link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  p.SockMapFD,
		Program: p.program,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
}
