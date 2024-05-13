package manager

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/ebpf-manager/tracefs"
)

type probeType uint8

const (
	kprobe probeType = iota
	uprobe
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

// attachKprobe - Attaches the probe to its kprobe
func (p *Probe) attachKprobe() error {
	var err error

	if len(p.HookFuncName) == 0 {
		return errors.New("HookFuncName, MatchFuncName or SyscallFuncName is required")
	}

	// currently the perf event open ABI doesn't allow to specify the max active parameter
	if p.KProbeMaxActive > 0 && p.isReturnProbe {
		if err = p.attachWithKprobeEvents(); err != nil {
			if p.perfEventFD, err = perfEventOpenPMU(p.HookFuncName, 0, -1, "kprobe", p.isReturnProbe, 0); err != nil {
				return err
			}
		}
	} else if p.KprobeAttachMethod == AttachKprobeWithPerfEventOpen {
		if p.perfEventFD, err = perfEventOpenPMU(p.HookFuncName, 0, -1, "kprobe", p.isReturnProbe, 0); err != nil {
			if err = p.attachWithKprobeEvents(); err != nil {
				return err
			}
		}
	} else if p.KprobeAttachMethod == AttachKprobeWithKprobeEvents {
		if err = p.attachWithKprobeEvents(); err != nil {
			if p.perfEventFD, err = perfEventOpenPMU(p.HookFuncName, 0, -1, "kprobe", p.isReturnProbe, 0); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("invalid kprobe attach method: %d", p.KprobeAttachMethod)
	}

	// enable perf event
	if err = ioctlPerfEventSetBPF(p.perfEventFD, p.program.FD()); err != nil {
		return fmt.Errorf("couldn't set perf event bpf %s: %w", p.ProbeIdentificationPair, err)
	}
	if err = ioctlPerfEventEnable(p.perfEventFD); err != nil {
		return fmt.Errorf("couldn't enable perf event %s: %w", p.ProbeIdentificationPair, err)
	}
	return nil
}

// attachWithKprobeEvents attaches the kprobe using the kprobes_events ABI
func (p *Probe) attachWithKprobeEvents() error {
	if p.kprobeHookPointNotExist {
		return ErrKProbeHookPointNotExist
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
	kprobeID, err := registerKprobeEvent(p.prefix(), p.HookFuncName, p.UID, maxActiveStr, p.attachPID)
	if errors.Is(err, ErrKprobeIDNotExist) {
		// The probe might have been loaded under a kernel generated event name. Clean up just in case.
		_ = unregisterTraceFSEvent("kprobe_events", getKernelGeneratedEventName(p.prefix(), p.HookFuncName))
		// fallback without KProbeMaxActive
		kprobeID, err = registerKprobeEvent(p.prefix(), p.HookFuncName, p.UID, "", p.attachPID)
	}

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			p.kprobeHookPointNotExist = true
		}
		return fmt.Errorf("couldn't enable kprobe %s: %w", p.ProbeIdentificationPair, err)
	}

	// create perf event fd
	p.perfEventFD, err = perfEventOpenTracingEvent(kprobeID, -1)
	if err != nil {
		return fmt.Errorf("couldn't open perf event fd for %s: %w", p.ProbeIdentificationPair, err)
	}
	p.attachedWithDebugFS = true

	return nil
}

// detachKprobe - Detaches the probe from its kprobe
func (p *Probe) detachKprobe() error {
	if !p.attachedWithDebugFS {
		// nothing to do
		return nil
	}

	// Write kprobe_events line to remove hook point
	return unregisterKprobeEvent(p.prefix(), p.HookFuncName, p.UID, p.attachPID)
}

func (p *Probe) pauseKprobe() error {
	if err := ioctlPerfEventDisable(p.perfEventFD); err != nil {
		return fmt.Errorf("pause kprobe: %w", err)
	}
	return nil
}

func (p *Probe) resumeKprobe() error {
	if err := ioctlPerfEventEnable(p.perfEventFD); err != nil {
		return fmt.Errorf("resume kprobe: %w", err)
	}
	return nil
}

// registerKprobeEvent - Writes a new kprobe in kprobe_events with the provided parameters. Call DisableKprobeEvent
// to remove the kprobe.
func registerKprobeEvent(probeType, funcName, UID, maxActiveStr string, kprobeAttachPID int) (int, error) {
	// Generate event name
	eventName, err := generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return -1, err
	}

	// Write line to kprobe_events
	f, err := tracefs.OpenFile("kprobe_events", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, fmt.Errorf("cannot open kprobe_events: %w", err)
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxActiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, fmt.Errorf("cannot write %q to kprobe_events: %w", cmd, err)
	}

	// Retrieve kprobe ID
	kprobeIDFile := fmt.Sprintf("events/kprobes/%s/id", eventName)
	kprobeIDBytes, err := tracefs.ReadFile(kprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrKprobeIDNotExist
		}
		return -1, fmt.Errorf("cannot read kprobe id: %w", err)
	}
	id := strings.TrimSpace(string(kprobeIDBytes))
	kprobeID, err := strconv.Atoi(id)
	if err != nil {
		return -1, fmt.Errorf("invalid kprobe id: '%s': %w", id, err)
	}
	return kprobeID, nil
}

// unregisterKprobeEvent - Removes a kprobe from kprobe_events
func unregisterKprobeEvent(probeType, funcName, UID string, kprobeAttachPID int) error {
	// Generate event name
	eventName, err := generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return err
	}
	return unregisterTraceFSEvent("kprobe_events", eventName)
}
