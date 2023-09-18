package manager

import (
	"fmt"
	"strings"
)

// attachTracepoint - Attaches the probe to its tracepoint
func (p *Probe) attachTracepoint() error {
	// Parse section
	if len(p.TracepointCategory) == 0 || len(p.TracepointName) == 0 {
		traceGroup := strings.SplitN(p.programSpec.SectionName, "/", 3)
		if len(traceGroup) != 3 {
			return fmt.Errorf("expected SEC(\"tracepoint/[category]/[name]\") got %s: %w", p.programSpec.SectionName, ErrSectionFormat)
		}
		p.TracepointCategory = traceGroup[1]
		p.TracepointName = traceGroup[2]
	}

	// Get the ID of the tracepoint to activate
	tracepointID, err := GetTracepointID(p.TracepointCategory, p.TracepointName)
	if err != nil {
		return fmt.Errorf("couldn't activate tracepoint %s: %w", p.ProbeIdentificationPair, err)
	}

	// Hook the eBPF program to the tracepoint
	p.perfEventFD, err = perfEventOpenTracingEvent(tracepointID, -1)
	if err != nil {
		return fmt.Errorf("couldn't enable tracepoint %s: %w", p.ProbeIdentificationPair, err)
	}
	if err = ioctlPerfEventSetBPF(p.perfEventFD, p.program.FD()); err != nil {
		return fmt.Errorf("couldn't set perf event bpf %s: %w", p.ProbeIdentificationPair, err)
	}
	if err = ioctlPerfEventEnable(p.perfEventFD); err != nil {
		return fmt.Errorf("couldn't enable perf event %s: %w", p.ProbeIdentificationPair, err)
	}
	return nil
}

func (p *Probe) pauseTracepoint() error {
	if err := ioctlPerfEventDisable(p.perfEventFD); err != nil {
		return fmt.Errorf("pause tracepoint: %w", err)
	}
	return nil
}

func (p *Probe) resumeTracepoint() error {
	if err := ioctlPerfEventEnable(p.perfEventFD); err != nil {
		return fmt.Errorf("resume tracepoint: %w", err)
	}
	return nil
}
