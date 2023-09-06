package manager

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// perfEventOpenPMU - Kernel API with e12f03d ("perf/core: Implement the 'perf_kprobe' PMU") allows
// creating [k,u]probe with perf_event_open, which makes it easier to clean up
// the [k,u]probe. This function tries to create pfd with the perf_kprobe PMU.
func perfEventOpenPMU(name string, offset, pid int, eventType string, retProbe bool, referenceCounterOffset uint64) (*fd, error) {
	var err error
	var attr unix.PerfEventAttr

	// Getting the PMU type will fail if the kernel doesn't support
	// the perf_[k,u]probe PMU.
	attr.Type, err = getPMUEventType(eventType)
	if err != nil {
		return nil, err
	}

	if retProbe {
		var retProbeBit uint64
		retProbeBit, err = getRetProbeBit(eventType)
		if err != nil {
			return nil, err
		}
		attr.Config |= 1 << retProbeBit
	}

	if referenceCounterOffset > 0 {
		attr.Config |= referenceCounterOffset << 32
	}

	// transform the symbol name or the uprobe path to a byte array
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("couldn't create pointer to string %s: %w", name, err)
	}

	switch eventType {
	case "kprobe":
		attr.Ext1 = uint64(uintptr(unsafe.Pointer(namePtr))) // Kernel symbol to trace
		pid = 0
	case "uprobe":
		// The minimum size required for PMU uprobes is PERF_ATTR_SIZE_VER1,
		// since it added the config2 (Ext2) field. The Size field controls the
		// size of the internal buffer the kernel allocates for reading the
		// perf_event_attr argument from userspace.
		attr.Size = unix.PERF_ATTR_SIZE_VER1
		attr.Ext1 = uint64(uintptr(unsafe.Pointer(namePtr))) // Uprobe path
		attr.Ext2 = uint64(offset)                           // Uprobe offset
		// PID filter is only possible for uprobe events
		if pid <= 0 {
			pid = -1
		}
	}

	var efd int
	efd, err = unix.PerfEventOpen(&attr, pid, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)

	// Since commit 97c753e62e6c, ENOENT is correctly returned instead of EINVAL
	// when trying to create a kretprobe for a missing symbol. Make sure ENOENT
	// is returned to the caller.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EINVAL) {
		return nil, fmt.Errorf("symbol '%s' not found: %w", name, syscall.EINVAL)
	}
	if err != nil {
		return nil, fmt.Errorf("opening perf event: %w", err)
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(unsafe.Pointer(namePtr))

	return newFD(uint32(efd)), nil
}

func perfEventOpenTracingEvent(probeID int, pid int) (*fd, error) {
	if pid <= 0 {
		pid = -1
	}
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(probeID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	return perfEventOpenRaw(&attr, pid, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
}

func perfEventOpenRaw(attr *unix.PerfEventAttr, pid int, cpu int, groupFd int, flags int) (*fd, error) {
	efd, err := unix.PerfEventOpen(attr, pid, cpu, groupFd, flags)
	if efd < 0 {
		return nil, fmt.Errorf("perf_event_open error: %v", err)
	}
	return newFD(uint32(efd)), nil
}

func ioctlPerfEventSetBPF(perfEventOpenFD *fd, progFD int) error {
	return unix.IoctlSetInt(int(perfEventOpenFD.raw), unix.PERF_EVENT_IOC_SET_BPF, progFD)
}

func ioctlPerfEventEnable(perfEventOpenFD *fd) error {
	return unix.IoctlSetInt(int(perfEventOpenFD.raw), unix.PERF_EVENT_IOC_ENABLE, 0)
}

func ioctlPerfEventDisable(perfEventOpenFD *fd) error {
	return unix.IoctlSetInt(int(perfEventOpenFD.raw), unix.PERF_EVENT_IOC_DISABLE, 0)
}

func sockAttach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, progFd)
}

func sockDetach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, progFd)
}
