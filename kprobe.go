package manager

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/ebpf-manager/tracefs"
)

type KprobeAttachMethod = AttachMethod

const (
	AttachKprobeMethodNotSet      = AttachMethodNotSet
	AttachKprobeWithPerfEventOpen = AttachWithPerfEventOpen
	AttachKprobeWithKprobeEvents  = AttachWithProbeEvents
)

func (p *Probe) prefix() string {
	if p.isReturnProbe {
		return "r"
	}
	return "p"
}

type attachFunc func() (*tracefsLink, error)

// attachKprobe - Attaches the probe to its kprobe
func (p *Probe) attachKprobe() error {
	if len(p.HookFuncName) == 0 {
		return fmt.Errorf("HookFuncName, MatchFuncName or SyscallFuncName is required")
	}

	var eventsFunc attachFunc = p.attachWithKprobeEvents
	var pmuFunc attachFunc = func() (*tracefsLink, error) {
		pfd, err := perfEventOpenPMU(p.HookFuncName, 0, -1, "kprobe", p.isReturnProbe, 0)
		if err != nil {
			return nil, err
		}
		return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: kprobe}, nil
	}

	startFunc, fallbackFunc := pmuFunc, eventsFunc
	// currently the perf event open ABI doesn't allow to specify the max active parameter
	if (p.KProbeMaxActive > 0 && p.isReturnProbe) || p.KprobeAttachMethod == AttachKprobeWithKprobeEvents {
		startFunc, fallbackFunc = eventsFunc, pmuFunc
	}

	var err error
	var tl *tracefsLink
	if tl, err = startFunc(); err != nil {
		if tl, err = fallbackFunc(); err != nil {
			return err
		}
	}

	if err := attachPerfEvent(tl.perfEventLink, p.program); err != nil {
		_ = tl.Close()
		return fmt.Errorf("attach %s: %w", p.ProbeIdentificationPair, err)
	}
	p.progLink = tl
	return nil
}

// attachWithKprobeEvents attaches the kprobe using the kprobes_events ABI
func (p *Probe) attachWithKprobeEvents() (*tracefsLink, error) {
	if p.kprobeHookPointNotExist {
		return nil, ErrKProbeHookPointNotExist
	}

	// Prepare kprobe_events line parameters
	var maxActiveStr string
	if p.isReturnProbe {
		if p.KProbeMaxActive > 0 {
			maxActiveStr = fmt.Sprintf("%d", p.KProbeMaxActive)
		}
	}

	// Fallback to debugfs, write kprobe_events line to register kprobe
	var kprobeID int
	var eventName string
	kprobeID, eventName, err := registerKprobeEvent(p.prefix(), p.HookFuncName, p.UID, maxActiveStr, p.attachPID)
	if errors.Is(err, ErrKprobeIDNotExist) {
		// The probe might have been loaded under a kernel generated event name. Clean up just in case.
		_ = unregisterTraceFSEvent("kprobe_events", getKernelGeneratedEventName(p.prefix(), p.HookFuncName))
		// fallback without KProbeMaxActive
		kprobeID, eventName, err = registerKprobeEvent(p.prefix(), p.HookFuncName, p.UID, "", p.attachPID)
	}

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			p.kprobeHookPointNotExist = true
		}
		return nil, fmt.Errorf("couldn't enable kprobe %s: %w", p.ProbeIdentificationPair, err)
	}

	// create perf event fd
	pfd, err := perfEventOpenTracingEvent(kprobeID, -1)
	if err != nil {
		return nil, fmt.Errorf("couldn't open perf event fd for %s: %w", p.ProbeIdentificationPair, err)
	}
	return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: kprobe, EventName: eventName}, nil
}

// registerKprobeEvent - Writes a new kprobe in kprobe_events with the provided parameters. Call DisableKprobeEvent
// to remove the kprobe.
func registerKprobeEvent(probeType, funcName, UID, maxActiveStr string, kprobeAttachPID int) (int, string, error) {
	// Generate event name
	eventName, err := generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return -1, "", err
	}

	// Write line to kprobe_events
	f, err := tracefs.OpenFile("kprobe_events", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, "", fmt.Errorf("cannot open kprobe_events: %w", err)
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxActiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, "", fmt.Errorf("cannot write %q to kprobe_events: %w", cmd, err)
	}

	// Retrieve kprobe ID
	kprobeIDFile := fmt.Sprintf("events/kprobes/%s/id", eventName)
	kprobeIDBytes, err := tracefs.ReadFile(kprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, "", ErrKprobeIDNotExist
		}
		return -1, "", fmt.Errorf("cannot read kprobe id: %w", err)
	}
	id := strings.TrimSpace(string(kprobeIDBytes))
	kprobeID, err := strconv.Atoi(id)
	if err != nil {
		return -1, "", fmt.Errorf("invalid kprobe id: '%s': %w", id, err)
	}
	return kprobeID, eventName, nil
}
