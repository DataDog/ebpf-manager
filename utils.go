package manager

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// cache of the syscall prefix depending on kernel version
var syscallPrefix string

// GetSyscallFnName - Returns the kernel function of the provided syscall, after reading /proc/kallsyms to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnName(name string) (string, error) {
	return GetSyscallFnNameWithSymFile(name, defaultSymFile)
}

// GetSyscallFnNameWithSymFile - Returns the kernel function of the provided syscall, after reading symFile to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnNameWithSymFile(name string, symFile string) (string, error) {
	if symFile == "" {
		symFile = defaultSymFile
	}
	if syscallPrefix == "" {
		syscallName, err := getSyscallName("open", symFile)
		if err != nil {
			return "", err
		}
		// copy to avoid memory leak due to go subslice
		// see: https://go101.org/article/memory-leaking.html
		var b strings.Builder
		b.WriteString(syscallName)
		syscallName = b.String()

		syscallPrefix = strings.TrimSuffix(syscallName, "open")
	}

	return syscallPrefix + name, nil
}

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows bpf programs that may have been compiled
// for older syscall functions to run on newer kernels
func getSyscallName(name string, symFile string) (string, error) {
	// Get kernel symbols
	syms, err := os.Open(symFile)
	if err != nil {
		return "", err
	}
	defer syms.Close()

	return getSyscallFnNameWithKallsyms(name, syms, "")
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent io.Reader, arch string) (string, error) {
	if arch == "" {
		switch runtime.GOARCH {
		case "386":
			arch = "ia32"
		case "arm64":
			arch = "arm64"
		default:
			arch = "x64"
		}
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	newSyscall := regexp.MustCompile(`\b__` + arch + `_[Ss]y[sS]_` + name + `\b`)
	// If nothing found, search for old syscall function to be sure
	oldSyscall := regexp.MustCompile(`\b[Ss]y[sS]_` + name + `\b`)
	// check for '__' prefixed functions, like '__sys_open'
	prefixed := regexp.MustCompile(`\b__[Ss]y[sS]_` + name + `\b`)

	// the order of patterns is important
	// we first want to look for the new syscall format, then the old format, then the prefixed format
	patterns := []struct {
		pattern *regexp.Regexp
		result  string
	}{
		{newSyscall, ""},
		{oldSyscall, ""},
		{prefixed, ""},
	}

	scanner := bufio.NewScanner(kallsymsContent)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.Contains(line, name) {
			continue
		}

		for i := range patterns {
			p := &patterns[i]
			// if we already found a match for this pattern we continue
			if p.result != "" {
				continue
			}

			if res := p.pattern.FindString(line); res != "" {
				// fast path for first match on first pattern
				if i == 0 {
					return res, nil
				}

				p.result = res
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	for _, p := range patterns {
		if p.result != "" {
			return p.result, nil
		}
	}

	return "", fmt.Errorf("could not find a valid syscall name")
}

// errClosedFd - Use of closed file descriptor error
var errClosedFd = errors.New("use of closed file descriptor")

// fd - File descriptor
type fd struct {
	raw int64
}

// newFD - returns a new file descriptor
func newFD(value uint32) *fd {
	f := &fd{int64(value)}
	runtime.SetFinalizer(f, func(f *fd) {
		_ = f.Close()
	})
	return f
}

func (fd *fd) String() string {
	return strconv.FormatInt(fd.raw, 10)
}

func (fd *fd) Value() (uint32, error) {
	if fd.raw < 0 {
		return 0, errClosedFd
	}

	return uint32(fd.raw), nil
}

func (fd *fd) Close() error {
	if fd.raw < 0 {
		return nil
	}

	value := int(fd.raw)
	fd.raw = -1

	runtime.SetFinalizer(fd, nil)
	return unix.Close(value)
}

var (
	// kprobePMUType is used to cache the kprobe PMY type value
	kprobePMUType = struct {
		once  sync.Once
		value uint32
		err   error
	}{}
	// uprobePMUType is used to cache the uprobe PMU type value
	uprobePMUType = struct {
		once  sync.Once
		value uint32
		err   error
	}{}
)

func parsePMUEventType(eventType string) (uint32, error) {
	PMUTypeFile := fmt.Sprintf("/sys/bus/event_source/devices/%s/type", eventType)
	f, err := os.Open(PMUTypeFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("pmu type %s: %w", eventType, ErrNotSupported)
		}
		return 0, fmt.Errorf("couldn't open %s: %w", PMUTypeFile, err)
	}

	var t uint32
	_, err = fmt.Fscanf(f, "%d\n", &t)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse type at %s: %v", eventType, err)
	}
	return t, nil
}

// getPMUEventType reads a Performance Monitoring Unit's type (numeric identifier)
// from /sys/bus/event_source/devices/<pmu>/type.
func getPMUEventType(eventType string) (uint32, error) {
	switch eventType {
	case "kprobe":
		kprobePMUType.once.Do(func() {
			kprobePMUType.value, kprobePMUType.err = parsePMUEventType(eventType)
		})
		return kprobePMUType.value, kprobePMUType.err
	case "uprobe":
		uprobePMUType.once.Do(func() {
			uprobePMUType.value, uprobePMUType.err = parsePMUEventType(eventType)
		})
		return uprobePMUType.value, uprobePMUType.err
	default:
		return 0, fmt.Errorf("unknown event type: %s", eventType)
	}
}

var (
	// kprobeRetProbeBit is used to cache the KProbe RetProbe bit value
	kprobeRetProbeBit = struct {
		once  sync.Once
		value uint64
		err   error
	}{}
	// uprobeRetProbeBit is used to cache the UProbe RetProbe bit value
	uprobeRetProbeBit = struct {
		once  sync.Once
		value uint64
		err   error
	}{}
)

// parseRetProbeBit reads a Performance Monitoring Unit's retprobe bit
// from /sys/bus/event_source/devices/<pmu>/format/retprobe.
func parseRetProbeBit(eventType string) (uint64, error) {
	p := filepath.Join("/sys/bus/event_source/devices/", eventType, "/format/retprobe")

	data, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}

	var rp uint64
	n, err := fmt.Sscanf(string(bytes.TrimSpace(data)), "config:%d", &rp)
	if err != nil {
		return 0, fmt.Errorf("parse retprobe bit: %w", err)
	}
	if n != 1 {
		return 0, fmt.Errorf("parse retprobe bit: expected 1 item, got %d", n)
	}

	return rp, nil
}

func getRetProbeBit(eventType string) (uint64, error) {
	switch eventType {
	case "kprobe":
		kprobeRetProbeBit.once.Do(func() {
			kprobeRetProbeBit.value, kprobeRetProbeBit.err = parseRetProbeBit(eventType)
		})
		return kprobeRetProbeBit.value, kprobeRetProbeBit.err
	case "uprobe":
		uprobeRetProbeBit.once.Do(func() {
			uprobeRetProbeBit.value, uprobeRetProbeBit.err = parseRetProbeBit(eventType)
		})
		return uprobeRetProbeBit.value, uprobeRetProbeBit.err
	default:
		return 0, fmt.Errorf("unknown event type %s", eventType)
	}
}

// getEnv retrieves the environment variable key. If it does not exist it returns the default.
func getEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		all := make([]string, len(combineWith)+1)
		all[0] = value
		copy(all[1:], combineWith)
		return filepath.Join(all...)
	}
}

// hostProc returns joins the provided path with the host /proc directory
func hostProc(combineWith ...string) string {
	return getEnv("HOST_PROC", "/proc", combineWith...)
}

// Getpid returns the current process ID in the host namespace if $HOST_PROC is defined, the pid in the current namespace
// otherwise
func Getpid() int {
	p, err := os.Readlink(hostProc("/self"))
	if err == nil {
		if pid, err := strconv.ParseInt(p, 10, 32); err == nil {
			return int(pid)
		}
	}
	return os.Getpid()
}

// cleanupProgramSpec removes unused internal fields to free up some memory
func cleanupProgramSpec(spec *ebpf.ProgramSpec) {
	if spec != nil {
		spec.Instructions = nil
	}
}
