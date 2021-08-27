package manager

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	retry "github.com/avast/retry-go"
	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// XdpAttachMode selects a way how XDP program will be attached to interface
type XdpAttachMode int

const (
	// XdpAttachModeNone stands for "best effort" - kernel automatically
	// selects best mode (would try Drv first, then fallback to Generic).
	// NOTE: Kernel will not fallback to Generic XDP if NIC driver failed
	//       to install XDP program.
	XdpAttachModeNone XdpAttachMode = 0
	// XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
	// but does not requires driver support.
	XdpAttachModeSkb XdpAttachMode = (1 << 1)
	// XdpAttachModeDrv is native, driver mode (support from driver side required)
	XdpAttachModeDrv XdpAttachMode = (1 << 2)
	// XdpAttachModeHw suitable for NICs with hardware XDP support
	XdpAttachModeHw XdpAttachMode = (1 << 3)
)

type TrafficType uint32

const (
	Ingress = TrafficType(tc.HandleMinIngress)
	Egress  = TrafficType(tc.HandleMinEgress)
)

const (
	UnknownProbeType = ""
	ProbeType        = "p"
	RetProbeType     = "r"
)

type ProbeIdentificationPair struct {
	kprobeType string

	// UID - (optional) this field can be used to identify your probes when the same eBPF program is used on multiple
	// hook points. Keep in mind that the pair (probe section, probe UID) needs to be unique
	// system-wide for the kprobes and uprobes registration to work.
	UID string

	// EBPFFuncName - Name of the main eBPF function of your eBPF program.
	EBPFFuncName string

	// EBPFSection - Section in which EBPFFuncName lives.
	EBPFSection string
}

func (pip ProbeIdentificationPair) String() string {
	return fmt.Sprintf("{UID:%s EBPFSection:%s EBPFFuncName:%s}", pip.UID, pip.EBPFSection, pip.EBPFFuncName)
}

// Matches - Returns true if the identification pair (probe uid, probe section, probe func name) matches.
func (pip ProbeIdentificationPair) Matches(id ProbeIdentificationPair) bool {
	return pip.UID == id.UID && pip.EBPFDefinitionMatches(id)
}

// EBPFDefinitionMatches - Returns true if the eBPF definition matches.
func (pip ProbeIdentificationPair) EBPFDefinitionMatches(id ProbeIdentificationPair) bool {
	return pip.EBPFFuncName == id.EBPFFuncName && pip.EBPFSection == id.EBPFSection
}

// GetEBPFFuncName - Returns EBPFFuncName with the UID as a postfix if the Probe was copied
func (pip ProbeIdentificationPair) GetEBPFFuncName(isCopy bool) string {
	if isCopy {
		return pip.EBPFFuncName + pip.UID
	}
	return pip.EBPFFuncName
}

// GetKprobeType - Identifies the probe type of the provided KProbe section
func (pip ProbeIdentificationPair) GetKprobeType() string {
	if len(pip.kprobeType) == 0 {
		if strings.HasPrefix(pip.EBPFSection, "kretprobe/") {
			pip.kprobeType = RetProbeType
		} else if strings.HasPrefix(pip.EBPFSection, "kprobe/") {
			pip.kprobeType = ProbeType
		} else {
			pip.kprobeType = UnknownProbeType
		}
	}
	return pip.kprobeType
}

// GetUprobeType - Identifies the probe type of the provided Uprobe section
func (pip ProbeIdentificationPair) GetUprobeType() string {
	if len(pip.kprobeType) == 0 {
		if strings.HasPrefix(pip.EBPFSection, "uretprobe/") {
			pip.kprobeType = RetProbeType
		} else if strings.HasPrefix(pip.EBPFSection, "uprobe/") {
			pip.kprobeType = ProbeType
		} else {
			pip.kprobeType = UnknownProbeType
		}
	}
	return pip.kprobeType
}

// Probe - Main eBPF probe wrapper. This structure is used to store the required data to attach a loaded eBPF
// program to its hook point.
type Probe struct {
	manager            *Manager
	program            *ebpf.Program
	programSpec        *ebpf.ProgramSpec
	perfEventFD        *FD
	rawTracepointFD    *FD
	state              state
	stateLock          sync.RWMutex
	manualLoadNeeded   bool
	checkPin           bool
	attachPID          int
	attachRetryAttempt uint

	// lastError - stores the last error that the probe encountered, it is used to surface a more useful error message
	// when one of the validators (see Options.ActivatedProbes) fails.
	lastError error

	// ProbeIdentificationPair is used to identify the current probe
	ProbeIdentificationPair

	// CopyProgram - When enabled, this option will make a unique copy of the program section for the current program
	CopyProgram bool

	// SyscallFuncName - Name of the syscall on which the program should be hooked. As the exact kernel symbol may
	// differ from one kernel version to the other, the right prefix will be computed automatically at runtime.
	// If a syscall name is not provided, the section name (without its probe type prefix) is assumed to be the
	// hook point.
	SyscallFuncName string

	// MatchFuncName - Pattern used to find the function(s) to attach to
	// FOR KPROBES: When this field is used, the provided pattern is matched against the list of available symbols
	// in /sys/kernel/debug/tracing/available_filter_functions. If the exact function does not exist, then the first
	// symbol matching the provided pattern will be used. This option requires debugfs.
	//
	// FOR UPROBES: When this field is used, the provided pattern is matched against the list of symbols in the symbol
	// table of the provided elf binary. If the exact function does not exist, then the first symbol matching the
	// provided pattern will be used.
	MatchFuncName string

	// HookFuncName - Exact name of the symbol to hook onto. When this field is set, MatchFuncName and SyscallFuncName
	// are ignored.
	HookFuncName string

	// Enabled - Indicates if a probe should be enabled or not. This parameter can be set at runtime using the
	// Manager options (see ActivatedProbes)
	Enabled bool

	// PinPath - Once loaded, the eBPF program will be pinned to this path. If the eBPF program has already been pinned
	// and is already running in the kernel, then it will be loaded from this path.
	PinPath string

	// KProbeMaxActive - (kretprobes) With kretprobes, you can configure the maximum number of instances of the function that can be
	// probed simultaneously with maxactive. If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
	// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS. For kprobes, maxactive is ignored.
	KProbeMaxActive int

	// UprobeOffset - If UprobeOffset is provided, the uprobe will be attached to it directly without looking for the
	// symbol in the elf binary. If the file is a non-PIE executable, the provided address must be a virtual address,
	// otherwise it must be an offset relative to the file load address.
	UprobeOffset uint64

	// ProbeRetry - Defines the number of times that the probe will retry to attach / detach on error.
	ProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before the probe should retry to attach / detach on error.
	ProbeRetryDelay time.Duration

	// BinaryPath - (uprobes) A Uprobe is attached to a specific symbol in a user space binary. The offset is
	// automatically computed for the symbol name provided in the uprobe section ( SEC("uprobe/[symbol_name]") ).
	BinaryPath string

	// CGrouPath - (cgroup family programs) All CGroup programs are attached to a CGroup (v2). This field provides the
	// path to the CGroup to which the probe should be attached. The attach type is determined by the section.
	CGroupPath string

	// SocketFD - (socket filter) Socket filter programs are bound to a socket and filter the packets they receive
	// before they reach user space. The probe will be bound to the provided file descriptor
	SocketFD int

	// Ifindex - (TC classifier & XDP) Interface index used to identify the interface on which the probe will be
	// attached. If not set, fall back to Ifname.
	Ifindex int32

	// Ifname - (TC Classifier & XDP) Interface name on which the probe will be attached.
	Ifname string

	// IfindexNetns - (TC Classifier & XDP) Network namespace in which the network interface lives
	IfindexNetns uint64

	// XDPAttachMode - (XDP) XDP attach mode. If not provided the kernel will automatically select the best available
	// mode.
	XDPAttachMode XdpAttachMode

	// NetworkDirection - (TC classifier) Network traffic direction of the classifier. Can be either Ingress or Egress. Keep
	// in mind that if you are hooking on the host side of a virtuel ethernet pair, Ingress and Egress are inverted.
	NetworkDirection TrafficType

	// tcObject - (TC classifier) TC object created when the classifier was attached. It will be reused to delete it on
	// exit.
	tcObject *tc.Object
}

// Copy - Returns a copy of the current probe instance. Only the exported fields are copied.
func (p *Probe) Copy() *Probe {
	return &Probe{
		ProbeIdentificationPair: ProbeIdentificationPair{
			UID:          p.UID,
			EBPFFuncName: p.EBPFFuncName,
		},
		SyscallFuncName:  p.SyscallFuncName,
		MatchFuncName:    p.MatchFuncName,
		Enabled:          p.Enabled,
		PinPath:          p.PinPath,
		KProbeMaxActive:  p.KProbeMaxActive,
		BinaryPath:       p.BinaryPath,
		CGroupPath:       p.CGroupPath,
		SocketFD:         p.SocketFD,
		Ifindex:          p.Ifindex,
		Ifname:           p.Ifname,
		IfindexNetns:     p.IfindexNetns,
		XDPAttachMode:    p.XDPAttachMode,
		NetworkDirection: p.NetworkDirection,
		ProbeRetry:       p.ProbeRetry,
		ProbeRetryDelay:  p.ProbeRetryDelay,
	}
}

// GetLastError - Returns the last error that the probe encountered
func (p *Probe) GetLastError() error {
	return p.lastError
}

// IsRunning - Returns true if the probe was successfully initialized, started and is currently running.
func (p *Probe) IsRunning() bool {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return p.state == running
}

// IsInitialized - Returns true if the probe was successfully initialized, started and is currently running.
func (p *Probe) IsInitialized() bool {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return p.state >= initialized
}

// Test - Triggers the probe with the provided test data. Returns the length of the output, the raw output or an error.
func (p *Probe) Test(in []byte) (uint32, []byte, error) {
	return p.program.Test(in)
}

// Benchmark - Benchmark runs the Program with the given input for a number of times and returns the time taken per
// iteration.
//
// Returns the result of the last execution of the program and the time per run or an error. reset is called whenever
// the benchmark syscall is interrupted, and should be set to testing.B.ResetTimer or similar.
func (p *Probe) Benchmark(in []byte, repeat int, reset func()) (uint32, time.Duration, error) {
	return p.program.Benchmark(in, repeat, reset)
}

// InitWithOptions - Initializes a probe with options
func (p *Probe) InitWithOptions(manager *Manager, manualLoadNeeded bool, checkPin bool) error {
	if !p.Enabled {
		return nil
	}
	p.manager = manager
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	p.state = reset
	p.manualLoadNeeded = manualLoadNeeded
	p.checkPin = checkPin
	return p.init()
}

// Init - Initialize a probe
func (p *Probe) Init(manager *Manager) error {
	if !p.Enabled {
		return nil
	}
	p.manager = manager
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	p.state = reset
	return p.init()
}

func (p *Probe) Program() *ebpf.Program {
	return p.program
}

// init - Internal initialization function
func (p *Probe) init() error {
	// Load spec if necessary
	if p.manualLoadNeeded {
		prog, err := ebpf.NewProgramWithOptions(p.programSpec, p.manager.options.VerifierOptions.Programs)
		if err != nil {
			p.lastError = err
			return errors.Wrapf(err, "couldn't load new probe %v", p.ProbeIdentificationPair)
		}
		p.program = prog
	}

	// override section based on the CopyProgram parameter
	selector := p.GetEBPFFuncName(p.CopyProgram)

	// Retrieve eBPF program if one isn't already set
	if p.program == nil {
		prog, ok := p.manager.collection.Programs[selector]
		if !ok {
			p.lastError = ErrUnknownSectionOrFuncName
			return errors.Wrapf(ErrUnknownSectionOrFuncName, "couldn't find program %s", selector)
		}
		p.program = prog
		p.checkPin = true
	}

	if p.programSpec == nil {
		if p.programSpec, p.lastError = p.manager.getProbeProgramSpec(p.ProbeIdentificationPair); p.lastError != nil {
			return errors.Wrapf(ErrUnknownSectionOrFuncName, "couldn't find program spec %s", selector)
		}
	}

	if p.checkPin {
		// Pin program if needed
		if p.PinPath != "" {
			if err := p.program.Pin(p.PinPath); err != nil {
				p.lastError = err
				return errors.Wrapf(err, "couldn't pin program %s at %s", selector, p.PinPath)
			}
		}
		p.checkPin = false
	}

	// Update syscall function name with the correct arch prefix
	if p.SyscallFuncName != "" && len(p.HookFuncName) == 0 {
		var err error
		p.HookFuncName, err = GetSyscallFnNameWithSymFile(p.SyscallFuncName, p.manager.options.SymFile)
		if err != nil {
			p.lastError = err
			return err
		}
	}

	// Find function name match if required
	if p.MatchFuncName != "" && len(p.HookFuncName) == 0 {
		// if this is a kprobe or a kretprobe, look for the symbol now
		if p.GetKprobeType() != UnknownProbeType {
			var err error
			p.HookFuncName, err = FindFilterFunction(p.MatchFuncName)
			if err != nil {
				p.lastError = err
				return err
			}
		}
	}

	if len(p.HookFuncName) == 0 {
		// default back to the AttachTo field in Program, as parsed by Cilium
		p.HookFuncName = p.programSpec.AttachTo
	}

	// Resolve interface index if one is provided
	if p.Ifindex == 0 && p.Ifname != "" {
		inter, err := net.InterfaceByName(p.Ifname)
		if err != nil {
			p.lastError = err
			return errors.Wrapf(err, "couldn't find interface %v", p.Ifname)
		}
		p.Ifindex = int32(inter.Index)
	}

	// Default max active value
	if p.KProbeMaxActive == 0 {
		p.KProbeMaxActive = p.manager.options.DefaultKProbeMaxActive
	}

	// Default retry
	if p.ProbeRetry == 0 {
		if p.manager.options.DefaultProbeRetry > 0 {
			p.ProbeRetry = p.manager.options.DefaultProbeRetry
		}
	}
	// account for the initial attempt
	p.ProbeRetry++

	// Default retry delay
	if p.ProbeRetryDelay == 0 {
		p.ProbeRetryDelay = p.manager.options.DefaultProbeRetryDelay
	}

	// update probe state
	p.state = initialized
	return nil
}

// Attach - Attaches the probe to the right hook point in the kernel depending on the program type and the provided
// parameters.
func (p *Probe) Attach() error {
	return retry.Do(func() error {
		p.attachRetryAttempt++
		err := p.attach()
		if err == nil {
			return nil
		}

		// not available, not a temporary error
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EINVAL) {
			return nil
		}

		return err
	}, retry.Attempts(p.ProbeRetry), retry.Delay(p.ProbeRetryDelay))
}

// attach - Thread unsafe version of attach
func (p *Probe) attach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state >= running || !p.Enabled {
		return nil
	}
	if p.state < initialized {
		if p.lastError == nil {
			p.lastError = ErrProbeNotInitialized
		}
		return ErrProbeNotInitialized
	}

	// Per program type start
	var err error
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		err = errors.Wrap(ErrSectionFormat, "invalid program type, make sure to use the right section prefix")
	case ebpf.Kprobe:
		err = p.attachKprobe()
	case ebpf.TracePoint:
		err = p.attachTracepoint()
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl:
		err = p.attachCGroup()
	case ebpf.SocketFilter:
		err = p.attachSocket()
	case ebpf.SchedCLS:
		err = p.attachTCCLS()
	case ebpf.XDP:
		err = p.attachXDP()
	case ebpf.LSM:
		err = p.attachLSM()
	default:
		err = fmt.Errorf("program type %s not implemented yet", p.programSpec.Type)
	}
	if err != nil {
		p.lastError = err
		// Clean up any progress made in the attach attempt
		_ = p.stop(false)
		return errors.Wrapf(err, "couldn't start probe %s", p.ProbeIdentificationPair)
	}

	// update probe state
	p.state = running
	p.attachRetryAttempt = p.ProbeRetry
	return nil
}

// Detach - Detaches the probe from its hook point depending on the program type and the provided parameters. This
// method does not close the underlying eBPF program, which means that Attach can be called again later.
func (p *Probe) Detach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < running || !p.Enabled {
		return nil
	}

	// detach from hook point
	err := p.detachRetry()

	// update state of the probe
	if err != nil {
		p.lastError = err
	} else {
		p.state = initialized
	}

	return err
}

// detachRetry - Thread unsafe version of Detach with retry
func (p *Probe) detachRetry() error {
	return retry.Do(p.detach, retry.Attempts(p.ProbeRetry), retry.Delay(p.ProbeRetryDelay))
}

// detach - Thread unsafe version of Detach.
func (p *Probe) detach() error {
	var err error
	// Remove pin if needed
	if p.PinPath != "" {
		err = ConcatErrors(err, os.Remove(p.PinPath))
	}

	// Shared with all probes: close the perf event file descriptor
	if p.perfEventFD != nil {
		err = p.perfEventFD.Close()
	}

	// Per program type cleanup
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		// nothing to do
		break
	case ebpf.Kprobe:
		err = ConcatErrors(err, p.detachKprobe())
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl:
		err = ConcatErrors(err, p.detachCgroup())
	case ebpf.SocketFilter:
		err = ConcatErrors(err, p.detachSocket())
	case ebpf.SchedCLS:
		err = ConcatErrors(err, p.detachTCCLS())
	case ebpf.XDP:
		err = ConcatErrors(err, p.detachXDP())
	case ebpf.LSM:
		err = ConcatErrors(err, p.detachLSM())
	default:
		// unsupported section, nothing to do either
		break
	}
	return err
}

// Stop - Detaches the probe from its hook point and close the underlying eBPF program.
func (p *Probe) Stop() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < running || !p.Enabled {
		p.reset()
		return nil
	}
	return p.stop(true)
}

func (p *Probe) stop(saveStopError bool) error {
	// detach from hook point
	err := p.detachRetry()

	// close the loaded program
	if p.attachRetryAttempt >= p.ProbeRetry {
		err = ConcatErrors(err, p.program.Close())
	}

	// update state of the probe
	if saveStopError {
		p.lastError = ConcatErrors(p.lastError, err)
	}

	// Cleanup probe if stop was successful
	if err == nil && p.attachRetryAttempt >= p.ProbeRetry {
		p.reset()
	}
	return errors.Wrapf(err, "couldn't stop probe %s", p.ProbeIdentificationPair)
}

// reset - Cleans up the internal fields of the probe
func (p *Probe) reset() {
	p.kprobeType = ""
	p.manager = nil
	p.program = nil
	p.programSpec = nil
	p.perfEventFD = nil
	p.rawTracepointFD = nil
	p.state = reset
	p.manualLoadNeeded = false
	p.checkPin = false
	p.attachPID = 0
	p.attachRetryAttempt = 0
}

// attachKprobe - Attaches the probe to its kprobe
func (p *Probe) attachKprobe() error {
	var err error

	if len(p.HookFuncName) == 0 {
		return errors.New("HookFuncName, MatchFuncName or SyscallFuncName is required")
	}

	// Prepare kprobe_events line parameters
	var maxActiveStr string
	if p.GetKprobeType() == RetProbeType {
		if p.KProbeMaxActive > 0 {
			maxActiveStr = fmt.Sprintf("%d", p.KProbeMaxActive)
		}
	}

	if p.GetKprobeType() == UnknownProbeType {
		// this might actually be a UProbe
		return p.attachUprobe()
	}

	p.attachPID = os.Getpid()

	// Write kprobe_events line to register kprobe
	kprobeID, err := EnableKprobeEvent(p.GetKprobeType(), p.HookFuncName, p.UID, maxActiveStr, p.attachPID)
	if err == ErrKprobeIDNotExist {
		// The probe might have been loaded under a kernel generated event name. Clean up just in case.
		_ = disableKprobeEvent(getKernelGeneratedEventName(p.GetKprobeType(), p.HookFuncName))
		// fallback without KProbeMaxActive
		kprobeID, err = EnableKprobeEvent(p.GetKprobeType(), p.HookFuncName, p.UID, "", p.attachPID)
	}
	if err != nil {
		return errors.Wrapf(err, "couldn't enable kprobe %s", p.ProbeIdentificationPair)
	}

	// Activate perf event
	p.perfEventFD, err = perfEventOpenTracepoint(kprobeID, p.program.FD())
	return errors.Wrapf(err, "couldn't enable kprobe %s", p.ProbeIdentificationPair)
}

// detachKprobe - Detaches the probe from its kprobe
func (p *Probe) detachKprobe() error {
	// Prepare kprobe_events line parameters
	if p.GetKprobeType() == UnknownProbeType {
		// this might be a Uprobe
		return p.detachUprobe()
	}

	// Write kprobe_events line to remove hook point
	return DisableKprobeEvent(p.GetKprobeType(), p.HookFuncName, p.UID, p.attachPID)
}

// attachTracepoint - Attaches the probe to its tracepoint
func (p *Probe) attachTracepoint() error {
	// Parse section
	traceGroup := strings.SplitN(p.EBPFSection, "/", 3)
	if len(traceGroup) != 3 {
		return errors.Wrapf(ErrSectionFormat, "expected SEC(\"tracepoint/[category]/[name]\") got %s", p.EBPFSection)
	}
	category := traceGroup[1]
	name := traceGroup[2]

	// Get the ID of the tracepoint to activate
	tracepointID, err := GetTracepointID(category, name)
	if err != nil {
		return errors.Wrapf(err, "couldn's activate tracepoint %s", p.ProbeIdentificationPair)
	}

	// Hook the eBPF program to the tracepoint
	p.perfEventFD, err = perfEventOpenTracepoint(tracepointID, p.program.FD())
	return errors.Wrapf(err, "couldn't enable tracepoint %s", p.ProbeIdentificationPair)
}

// attachUprobe - Attaches the probe to its Uprobe
func (p *Probe) attachUprobe() error {
	// Prepare uprobe_events line parameters
	p.attachPID = os.Getpid()

	if p.GetUprobeType() == UnknownProbeType {
		// unknown type
		return errors.Wrapf(ErrSectionFormat, "program type unrecognized in %s", p.ProbeIdentificationPair)
	}

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
			return errors.Wrapf(err, "failed to compile pattern %s", funcPattern)
		}

		// Retrieve dynamic symbol offset
		offsets, err := FindSymbolOffsets(p.BinaryPath, pattern)
		if err != nil {
			return errors.Wrapf(err, "couldn't find symbol matching %s in %s", pattern.String(), p.BinaryPath)
		}
		p.UprobeOffset = offsets[0].Value
		p.HookFuncName = offsets[0].Name
	}

	// enable uprobe
	uprobeID, err := EnableUprobeEvent(p.GetUprobeType(), p.HookFuncName, p.BinaryPath, p.UID, p.attachPID, p.UprobeOffset)
	if err != nil {
		return errors.Wrapf(err, "couldn't enable uprobe %s", p.ProbeIdentificationPair)
	}

	// Activate perf event
	p.perfEventFD, err = perfEventOpenTracepoint(uprobeID, p.program.FD())
	return errors.Wrapf(err, "couldn't enable uprobe %s", p.ProbeIdentificationPair)
}

// detachUprobe - Detaches the probe from its Uprobe
func (p *Probe) detachUprobe() error {
	// Prepare uprobe_events line parameters
	if p.GetUprobeType() == UnknownProbeType {
		// unknown type
		return errors.Wrapf(ErrSectionFormat, "program type unrecognized in section %v", p.ProbeIdentificationPair)
	}

	// Write uprobe_events line to remove hook point
	return DisableUprobeEvent(p.GetUprobeType(), p.HookFuncName, p.UID, p.attachPID)
}

// attachCGroup - Attaches the probe to a cgroup hook point
func (p *Probe) attachCGroup() error {
	// open CGroupPath
	f, err := os.Open(p.CGroupPath)
	if err != nil {
		return errors.Wrapf(err, "error opening cgroup %s from probe %s", p.CGroupPath, p.ProbeIdentificationPair)
	}
	defer f.Close()

	// Attach CGroup
	ret, err := bpfProgAttach(p.program.FD(), int(f.Fd()), p.programSpec.AttachType)
	if ret < 0 {
		return errors.Wrapf(err, "failed to attach probe %v to cgroup %s", p.ProbeIdentificationPair, p.CGroupPath)
	}
	return nil
}

// detachCGroup - Detaches the probe from its cgroup hook point
func (p *Probe) detachCgroup() error {
	// open CGroupPath
	f, err := os.Open(p.CGroupPath)
	if err != nil {
		return errors.Wrapf(err, "error opening cgroup %s from probe %s", p.CGroupPath, p.ProbeIdentificationPair)
	}

	// Detach CGroup
	ret, err := bpfProgDetach(p.program.FD(), int(f.Fd()), p.programSpec.AttachType)
	if ret < 0 {
		return errors.Wrapf(err, "failed to detach probe %v from cgroup %s", p.ProbeIdentificationPair, p.CGroupPath)
	}
	return nil
}

// attachSocket - Attaches the probe to the provided socket
func (p *Probe) attachSocket() error {
	return sockAttach(p.SocketFD, p.program.FD())
}

// detachSocket - Detaches the probe from its socket
func (p *Probe) detachSocket() error {
	return sockDetach(p.SocketFD, p.program.FD())
}

// attachTCCLS - Attaches the probe to its TC classifier hook point
func (p *Probe) attachTCCLS() error {
	var err error
	// Make sure Ifindex is properly set
	if p.Ifindex == 0 && p.Ifname == "" {
		return ErrInterfaceNotSet
	}

	// Recover the netlink socket of the interface from the manager
	ntl, ok := p.manager.netlinkCache[netlinkCacheKey{p.Ifindex, p.IfindexNetns}]
	if !ok {
		// Set up new netlink connection
		ntl, err = p.manager.newNetlinkConnection(p.Ifindex, p.IfindexNetns)
		if err != nil {
			return err
		}
	}

	// Create a Qdisc for the provided interface
	qdisc := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(p.Ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Add the Qdisc
	err = ntl.rtNetlink.Qdisc().Add(qdisc)
	if err != nil {
		if err.Error() != "netlink receive: file exists" {
			return errors.Wrapf(err, "couldn't add a \"clsact\" qdisc to interface %v", p.Ifindex)
		}
	}

	// Create qdisc filter
	fd := uint32(p.program.FD())
	flag := uint32(1)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(p.Ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, uint32(p.NetworkDirection)),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",

			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  &p.EBPFSection,
				Flags: &flag,
			},
		},
	}

	// Add qdisc filter
	err = ntl.rtNetlink.Filter().Add(&filter)
	if err == nil {
		p.tcObject = qdisc
		ntl.schedClsCount++
	}
	return errors.Wrapf(err, "couldn't add a %v filter to interface %v: %v", p.NetworkDirection, p.Ifindex, err)
}

// detachTCCLS - Detaches the probe from its TC classifier hook point
func (p *Probe) detachTCCLS() error {
	// Recover the netlink socket of the interface from the manager
	ntl, ok := p.manager.netlinkCache[netlinkCacheKey{p.Ifindex, p.IfindexNetns}]
	if !ok {
		return fmt.Errorf("couldn't find qdisc from which the probe %v was meant to be detached", p.ProbeIdentificationPair)
	}

	if ntl.schedClsCount >= 2 {
		ntl.schedClsCount--
		// another classifier is still using the qdisc, do not delete it yet
		return nil
	}

	// Delete qdisc
	err := ntl.rtNetlink.Qdisc().Delete(p.tcObject)
	return errors.Wrapf(err, "couldn't detach TC classifier of probe %v", p.ProbeIdentificationPair)
}

// attachXDP - Attaches the probe to an interface with an XDP hook point
func (p *Probe) attachXDP() error {
	// Lookup interface
	link, err := netlink.LinkByIndex(int(p.Ifindex))
	if err != nil {
		return errors.Wrapf(err, "couldn't retrieve interface %v", p.Ifindex)
	}

	// Attach program
	err = netlink.LinkSetXdpFdWithFlags(link, p.program.FD(), int(p.XDPAttachMode))
	return errors.Wrapf(err, "couldn't attach XDP program %v to interface %v", p.ProbeIdentificationPair, p.Ifindex)
}

// detachXDP - Detaches the probe from its XDP hook point
func (p *Probe) detachXDP() error {
	// Lookup interface
	link, err := netlink.LinkByIndex(int(p.Ifindex))
	if err != nil {
		return errors.Wrapf(err, "couldn't retrieve interface %v", p.Ifindex)
	}

	// Detach program
	err = netlink.LinkSetXdpFdWithFlags(link, -1, int(p.XDPAttachMode))
	return errors.Wrapf(err, "couldn't detach XDP program %v from interface %v", p.ProbeIdentificationPair, p.Ifindex)
}

// attachLSM - Attaches the probe to its LSM hook point
func (p *Probe) attachLSM() error {
	var err error
	p.rawTracepointFD, err = rawTracepointOpen("", p.program.FD())
	if err != nil {
		return errors.Wrapf(err, "failed to attach LSM hook point")
	}
	return nil
}

// detachLSM - Detaches the probe from its LSM hook point
func (p *Probe) detachLSM() error {
	if p.rawTracepointFD != nil {
		return errors.Wrapf(p.rawTracepointFD.Close(), "failed to detach LSM hook point")
	}
	return nil
}
