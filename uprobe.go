package manager

import (
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/ebpf-manager/tracefs"
)

// SanitizeUprobeAddresses - sanitizes the addresses of the provided symbols
func SanitizeUprobeAddresses(f *elf.File, syms []elf.Symbol) {
	// If the binary is a non-PIE executable, addr must be a virtual address, otherwise it must be an offset relative to
	// the file load address. For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate the virtual
	// address to physical address in the binary file.
	if f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN {
		for i, sym := range syms {
			for _, prog := range f.Progs {
				if prog.Type == elf.PT_LOAD {
					if sym.Value >= prog.Vaddr && sym.Value < (prog.Vaddr+prog.Memsz) {
						syms[i].Value = sym.Value - prog.Vaddr + prog.Off
					}
				}
			}
		}
	}
}

// OpenAndListSymbols - Opens an elf file and extracts all its symbols
func OpenAndListSymbols(path string) (*elf.File, []elf.Symbol, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't open elf file %s: %w", path, err)
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = fmt.Errorf("failed to list symbols: %v", errSyms)
		}
		if errDynSyms != nil {
			err = fmt.Errorf("failed to list dynamic symbols: %v", errDynSyms)
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("no symbols found")
	}
	return f, syms, nil
}

// findSymbolOffsets - Parses the provided file and returns the offsets of the symbols that match the provided pattern
func findSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
	f, syms, err := OpenAndListSymbols(path)
	if err != nil {
		return nil, err
	}

	var matches []elf.Symbol
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && pattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if len(matches) == 0 {
		return nil, ErrSymbolNotFound
	}

	SanitizeUprobeAddresses(f, matches)
	return matches, nil
}

// attachWithUprobeEvents attaches the uprobe using the uprobes_events ABI
func (p *Probe) attachWithUprobeEvents() (*tracefsLink, error) {
	var uprobeID int
	var eventName string
	uprobeID, eventName, err := registerUprobeEvent(p.prefix(), p.HookFuncName, p.BinaryPath, p.UID, p.attachPID, p.UprobeOffset)
	if err != nil {
		return nil, fmt.Errorf("couldn't enable uprobe %s: %w", p.ProbeIdentificationPair, err)
	}

	pfd, err := perfEventOpenTracingEvent(uprobeID, p.PerfEventPID)
	if err != nil {
		return nil, fmt.Errorf("couldn't open perf event fd for %s: %w", p.ProbeIdentificationPair, err)
	}
	return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: uprobe, EventName: eventName}, nil
}

// attachUprobe - Attaches the probe to its Uprobe
func (p *Probe) attachUprobe() error {
	// compute the offset if it was not provided
	if p.UprobeOffset == 0 {
		var funcPattern string

		// find the offset of the first symbol matching the provided pattern
		if len(p.MatchFuncName) > 0 {
			funcPattern = p.MatchFuncName
		} else {
			funcPattern = fmt.Sprintf("^%s$", p.HookFuncName)
		}
		pattern, err := regexp.Compile(funcPattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern %s: %w", funcPattern, err)
		}

		// Retrieve dynamic symbol offset
		offsets, err := findSymbolOffsets(p.BinaryPath, pattern)
		if err != nil {
			return fmt.Errorf("couldn't find symbol matching %s in %s: %w", pattern.String(), p.BinaryPath, err)
		}
		p.UprobeOffset = offsets[0].Value
		p.HookFuncName = offsets[0].Name
	}

	var eventsFunc attachFunc = p.attachWithUprobeEvents
	var pmuFunc attachFunc = func() (*tracefsLink, error) {
		pfd, err := perfEventOpenPMU(p.BinaryPath, int(p.UprobeOffset), p.PerfEventPID, "uprobe", p.isReturnProbe, 0)
		if err != nil {
			return nil, err
		}
		return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: uprobe}, nil
	}

	startFunc, fallbackFunc := pmuFunc, eventsFunc
	if p.UprobeAttachMethod == AttachWithProbeEvents {
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

// registerUprobeEvent - Writes a new Uprobe in uprobe_events with the provided parameters. Call DisableUprobeEvent
// to remove the kprobe.
func registerUprobeEvent(probeType string, funcName, path, UID string, uprobeAttachPID int, offset uint64) (int, string, error) {
	// Generate event name
	eventName, err := generateEventName(probeType, funcName, UID, uprobeAttachPID)
	if err != nil {
		return -1, "", err
	}

	// Write line to uprobe_events, only eventName is tested to max MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)

	f, err := tracefs.OpenFile("uprobe_events", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, "", fmt.Errorf("cannot open uprobe_events: %w", err)
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)
	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, "", fmt.Errorf("cannot write %q to uprobe_events: %w", cmd, err)
	}

	// Retrieve Uprobe ID
	uprobeIDFile := fmt.Sprintf("events/uprobes/%s/id", eventName)
	uprobeIDBytes, err := tracefs.ReadFile(uprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, "", ErrUprobeIDNotExist
		}
		return -1, "", fmt.Errorf("cannot read uprobe id: %w", err)
	}
	uprobeID, err := strconv.Atoi(strings.TrimSpace(string(uprobeIDBytes)))
	if err != nil {
		return -1, "", fmt.Errorf("invalid uprobe id: %w", err)
	}

	return uprobeID, eventName, nil
}
