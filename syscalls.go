package manager

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
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
