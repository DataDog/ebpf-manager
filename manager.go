package manager

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// FunctionExcluder - An interface for types that can be used for `AdditionalExcludedFunctionCollector`
type FunctionExcluder interface {
	// ShouldExcludeFunction - Returns true if the function should be excluded
	ShouldExcludeFunction(name string, prog *ebpf.ProgramSpec) bool
	// CleanCaches - Is called when the manager is done with the excluder (for memory reclaiming for example)
	CleanCaches()
}

// Options - Options of a Manager. These options define how a manager should be initialized.
type Options struct {
	// ActivatedProbes - List of the probes that should be activated, identified by their identification string.
	// If the list is empty, all probes will be activated.
	ActivatedProbes []ProbesSelector

	// KeepUnmappedProgramSpecs - Defines if the manager should keep unmapped ProgramSpec instances in the collection.
	// Enable this feature if you're going to clone one of these ProgramSpec.
	KeepUnmappedProgramSpecs bool

	// ExcludedFunctions - A list of functions that should not even be verified. This list overrides the ActivatedProbes
	// list: since the excluded sections aren't loaded in the kernel, all the probes using those sections will be
	// deactivated.
	ExcludedFunctions []string

	// AdditionalExcludedFunctionCollector - A dynamic function excluder, allowing to exclude functions with a callback.
	AdditionalExcludedFunctionCollector FunctionExcluder

	// ExcludedMaps - A list of maps that should not be created.
	ExcludedMaps []string

	// ConstantsEditor - Post-compilation constant edition. See ConstantEditor for more.
	ConstantEditors []ConstantEditor

	// MapSpecEditor - Pre-loading MapSpec editors.
	MapSpecEditors map[string]MapSpecEditor

	// VerifierOptions - Defines the log level of the verifier and the size of its log buffer. Set to 0 to disable
	// logging and 1 to get a verbose output of the error. Increase the buffer size if the output is truncated.
	VerifierOptions ebpf.CollectionOptions

	// MapEditors - External map editor. The provided eBPF maps will overwrite the maps of the Manager if their names
	// match.
	// This is particularly useful to share maps across Managers (and therefore across isolated eBPF programs), without
	// having to use the MapRouter indirection. However, this technique only works before the eBPF programs are loaded,
	// and therefore before the Manager is started. The keys of the map are the names of the maps to edit, as defined
	// in their sections SEC("maps/[name]").
	MapEditors map[string]*ebpf.Map

	// MapEditorsIgnoreMissingMaps - If MapEditorsIgnoreMissingMaps is set to true, the map edition process will return an
	// error if a map was missing in at least one program
	MapEditorsIgnoreMissingMaps bool

	// MapRouter - External map routing. See MapRoute for more.
	MapRouter []MapRoute

	// InnerOuterMapSpecs - Defines the mapping between inner and outer maps. See InnerOuterMapSpec for more.
	InnerOuterMapSpecs []InnerOuterMapSpec

	// TailCallRouter - External tail call routing. See TailCallRoute for more.
	TailCallRouter []TailCallRoute

	// SymFile - Kernel symbol file. If not provided, the default `/proc/kallsyms` will be used.
	SymFile string

	// PerfRingBufferSize - Manager-level default value for the perf ring buffers. Defaults to the size of 1 page
	// on the system. See PerfMap.PerfRingBuffer for more.
	DefaultPerfRingBufferSize int

	// Watermark - Manager-level default value for the watermarks of the perf ring buffers.
	// See PerfMap.Watermark for more.
	DefaultWatermark int

	// DefaultKProbeMaxActive - Manager-level default value for the kprobe max active parameter.
	// See Probe.MaxActive for more.
	DefaultKProbeMaxActive int

	// DefaultKprobeAttachMethod - Manager-level default value for the Kprobe attach method. Defaults to AttachKprobeWithPerfEventOpen if unset.
	DefaultKprobeAttachMethod KprobeAttachMethod

	// DefaultUprobeAttachMethod - Manager-level default value for the Uprobe attach method. Defaults to AttachWithPerfEventOpen if unset.
	DefaultUprobeAttachMethod AttachMethod

	// ProbeRetry - Defines the number of times that a probe will retry to attach / detach on error.
	DefaultProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before a probe should retry to attach / detach on error.
	DefaultProbeRetryDelay time.Duration

	// RLimit - The maps & programs provided to the manager might exceed the maximum allowed memory lock.
	// `RLIMIT_MEMLOCK` If a limit is provided here it will be applied when the manager is initialized.
	RLimit *unix.Rlimit

	// KeepKernelBTF - Defines if the kernel types defined in VerifierOptions.Programs.KernelTypes and KernelModuleTypes should be cleaned up
	// once the manager is done using them. By default, the manager will clean them up to save up space. DISCLAIMER: if
	// your program uses "manager.CloneProgram", you might want to enable "KeepKernelBTF". As a workaround, you can also
	// try to strip as much as possible the content of "KernelTypes" to reduce the memory overhead.
	KeepKernelBTF bool

	// SkipPerfMapReaderStartup - Perf maps whose name is set to true with this option will not have their reader goroutine started when calling the manager.Start() function.
	// PerfMap.Start() can then be used to start reading events from the corresponding PerfMap.
	SkipPerfMapReaderStartup map[string]bool

	// SkipRingbufferReaderStartup - Ringbuffer maps whose name is set to true with this option will not have their reader goroutine started when calling the manager.Start() function.
	// RingBuffer.Start() can then be used to start reading events from the corresponding RingBuffer.
	SkipRingbufferReaderStartup map[string]bool

	// KernelModuleBTFLoadFunc is a function to provide custom loading of BTF for kernel modules on-demand as programs are loaded
	KernelModuleBTFLoadFunc func(kmodName string) (*btf.Spec, error)

	// BypassEnabled controls whether program bypass is enabled for this manager
	BypassEnabled bool
}

// InstructionPatcherFunc - A function that patches the instructions of a program
type InstructionPatcherFunc func(m *Manager) error

// Manager - Helper structure that manages multiple eBPF programs and maps
type Manager struct {
	collectionSpec     *ebpf.CollectionSpec
	collection         *ebpf.Collection
	options            Options
	netlinkSocketCache *netlinkSocketCache
	state              state
	stateLock          sync.RWMutex
	bypassIndexes      map[string]uint32
	maxBypassIndex     uint32

	// Probes - List of probes handled by the manager
	Probes []*Probe

	// Maps - List of maps handled by the manager. PerfMaps should not be defined here, but instead in the PerfMaps
	// section
	Maps []*Map

	// PerfMaps - List of perf ring buffers handled by the manager
	PerfMaps []*PerfMap

	// RingBuffers - List of perf ring buffers handled by the manager
	RingBuffers []*RingBuffer

	// DumpHandler - Callback function called when manager.DumpMaps() is called
	// and dump the current state (human-readable)
	DumpHandler func(w io.Writer, manager *Manager, mapName string, currentMap *ebpf.Map)

	// InstructionPatchers - Callback functions called before loading probes, to
	// provide user the ability to perform last minute instruction patching.
	InstructionPatchers []InstructionPatcherFunc
}

// DumpMaps - Write in the w writer argument human-readable info about eBPF maps
// Dumps the set of maps provided, otherwise dumping all maps with a DumpHandler set.
func (m *Manager) DumpMaps(w io.Writer, maps ...string) error {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return ErrManagerNotInitialized
	}

	if m.DumpHandler == nil {
		return nil
	}

	var mapsToDump map[string]struct{}
	if len(maps) > 0 {
		mapsToDump = make(map[string]struct{})
		for _, m := range maps {
			mapsToDump[m] = struct{}{}
		}
	}
	needDump := func(name string) bool {
		if mapsToDump == nil {
			// dump all maps
			return true
		}
		_, found := mapsToDump[name]
		return found
	}

	// Look in the list of maps
	for mapName, currentMap := range m.collection.Maps {
		if needDump(mapName) {
			m.DumpHandler(w, m, mapName, currentMap)
		}
	}
	return nil
}

// getMap - Thread unsafe version of GetMap
func (m *Manager) getMap(name string) (*ebpf.Map, bool, error) {
	eBPFMap, ok := m.collection.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.array, true, nil
		}
	}
	if perfMap, found := m.getPerfMap(name); found {
		return perfMap.array, true, nil
	}
	if ringBuffer, found := m.getRingBuffer(name); found {
		return ringBuffer.array, true, nil
	}
	return nil, false, nil
}

// GetMap - Return a pointer to the requested eBPF map
// name: name of the map, as defined by its section SEC("maps/[name]")
func (m *Manager) GetMap(name string) (*ebpf.Map, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	return m.getMap(name)
}

// GetMaps - Return the list of eBPF maps in the manager
func (m *Manager) GetMaps() (map[string]*ebpf.Map, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return nil, ErrManagerNotInitialized
	}

	output := make(map[string]*ebpf.Map, len(m.collection.Maps))
	for section, m := range m.collection.Maps {
		output[section] = m
	}
	return output, nil
}

// getMapSpec - Thread unsafe version of GetMapSpec
func (m *Manager) getMapSpec(name string) (*ebpf.MapSpec, bool, error) {
	eBPFMap, ok := m.collectionSpec.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.arraySpec, true, nil
		}
	}
	if perfMap, found := m.getPerfMap(name); found {
		return perfMap.arraySpec, true, nil
	}
	if ringBuffer, found := m.getRingBuffer(name); found {
		return ringBuffer.arraySpec, true, nil
	}
	return nil, false, nil
}

// GetMapSpec - Return a pointer to the requested eBPF MapSpec. This is useful when duplicating a map.
func (m *Manager) GetMapSpec(name string) (*ebpf.MapSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collectionSpec == nil || m.state < elfLoaded {
		return nil, false, ErrManagerNotELFLoaded
	}
	return m.getMapSpec(name)
}

// getPerfMap - Thread unsafe version of GetPerfMap
func (m *Manager) getPerfMap(name string) (*PerfMap, bool) {
	for _, perfMap := range m.PerfMaps {
		if perfMap.Name == name {
			return perfMap, true
		}
	}
	return nil, false
}

// GetPerfMap - Select a perf map by its name
func (m *Manager) GetPerfMap(name string) (*PerfMap, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getPerfMap(name)
}

// getRingBuffer - Thread unsafe version of GetRingBuffer
func (m *Manager) getRingBuffer(name string) (*RingBuffer, bool) {
	for _, ringBuffer := range m.RingBuffers {
		if ringBuffer.Name == name {
			return ringBuffer, true
		}
	}
	return nil, false
}

// GetRingBuffer - Select a ring buffer by its name
func (m *Manager) GetRingBuffer(name string) (*RingBuffer, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getRingBuffer(name)
}

// getProgram - Thread unsafe version of GetProgram
func (m *Manager) getProgram(id ProbeIdentificationPair) ([]*ebpf.Program, bool, error) {
	var programs []*ebpf.Program
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.EBPFFuncName == id.EBPFFuncName {
				programs = append(programs, probe.program)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collection.Programs[id.EBPFFuncName]
		return []*ebpf.Program{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.ProbeIdentificationPair == id {
			return []*ebpf.Program{probe.program}, true, nil
		}
	}
	return programs, false, nil
}

// GetProgram - Return a pointer to the requested eBPF program
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then all the programs matching the provided section are
// returned.
func (m *Manager) GetProgram(id ProbeIdentificationPair) ([]*ebpf.Program, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	return m.getProgram(id)
}

// GetPrograms - Return the list of eBPF programs in the manager
func (m *Manager) GetPrograms() (map[string]*ebpf.Program, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return nil, ErrManagerNotInitialized
	}

	return maps.Clone(m.collection.Programs), nil
}

// GetProgramSpecs - Return the list of eBPF program specs in the manager
func (m *Manager) GetProgramSpecs() (map[string]*ebpf.ProgramSpec, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collectionSpec == nil || m.state < elfLoaded {
		return nil, ErrManagerNotELFLoaded
	}

	return maps.Clone(m.collectionSpec.Programs), nil
}

// getProgramSpec - Thread unsafe version of GetProgramSpec
func (m *Manager) getProgramSpec(id ProbeIdentificationPair) ([]*ebpf.ProgramSpec, bool, error) {
	var programs []*ebpf.ProgramSpec
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.EBPFFuncName == id.EBPFFuncName {
				programs = append(programs, probe.programSpec)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collectionSpec.Programs[id.EBPFFuncName]
		return []*ebpf.ProgramSpec{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.ProbeIdentificationPair == id {
			return []*ebpf.ProgramSpec{probe.programSpec}, true, nil
		}
	}
	return programs, false, nil
}

// GetProgramSpec - Return a pointer to the requested eBPF program spec
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then the original program spec with the right section in the
// collection spec (if found) is return
func (m *Manager) GetProgramSpec(id ProbeIdentificationPair) ([]*ebpf.ProgramSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collectionSpec == nil || m.state < elfLoaded {
		return nil, false, ErrManagerNotELFLoaded
	}
	return m.getProgramSpec(id)
}

// getProbe - Thread unsafe version of GetProbe
func (m *Manager) getProbe(id ProbeIdentificationPair) (*Probe, bool) {
	for _, managerProbe := range m.Probes {
		if managerProbe.ProbeIdentificationPair == id {
			return managerProbe, true
		}
	}
	return nil, false
}

// GetProbe - Select a probe by its section and UID
func (m *Manager) GetProbe(id ProbeIdentificationPair) (*Probe, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getProbe(id)
}

// LoadELF loads the collection spec from the provided ELF reader
func (m *Manager) LoadELF(elf io.ReaderAt) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state > elfLoaded {
		return ErrManagerELFLoaded
	}
	return m.loadELF(elf)
}

func (m *Manager) loadELF(elf io.ReaderAt) error {
	// Load the provided elf buffer
	var err error
	m.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(elf)
	if err != nil {
		return err
	}
	m.state = elfLoaded
	return nil
}

// Init - Initialize the manager.
// elf: reader containing the eBPF bytecode, must be nil if LoadELF already called
func (m *Manager) Init(elf io.ReaderAt) error {
	return m.InitWithOptions(elf, Options{})
}

// InitWithOptions - Initialize the manager.
// elf: reader containing the eBPF bytecode, must be nil if LoadELF already called
// options: options provided to the manager to configure its initialization
func (m *Manager) InitWithOptions(elf io.ReaderAt, options Options) error {
	m.stateLock.Lock()
	if m.state > initialized {
		m.stateLock.Unlock()
		return ErrManagerRunning
	}

	m.options = options
	m.netlinkSocketCache = newNetlinkSocketCache()
	if m.options.DefaultPerfRingBufferSize == 0 {
		m.options.DefaultPerfRingBufferSize = os.Getpagesize()
	}

	// perform a quick sanity check on the provided probes and maps
	if err := m.sanityCheck(); err != nil {
		m.stateLock.Unlock()
		return err
	}

	// set resource limit if requested
	if m.options.RLimit != nil {
		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, m.options.RLimit)
		if err != nil {
			m.stateLock.Unlock()
			return fmt.Errorf("couldn't adjust RLIMIT_MEMLOCK: %w", err)
		}
	}

	if m.state < elfLoaded {
		if elf == nil {
			m.stateLock.Unlock()
			return fmt.Errorf("nil ELF reader")
		}

		if err := m.loadELF(elf); err != nil {
			m.stateLock.Unlock()
			return err
		}
	} else if elf != nil {
		m.stateLock.Unlock()
		return ErrManagerELFLoaded
	}

	if m.options.AdditionalExcludedFunctionCollector != nil {
		for key, prog := range m.collectionSpec.Programs {
			if m.options.AdditionalExcludedFunctionCollector.ShouldExcludeFunction(key, prog) {
				m.options.ExcludedFunctions = append(m.options.ExcludedFunctions, key)
			}
		}
		m.options.AdditionalExcludedFunctionCollector.CleanCaches()
	}

	// Remove excluded programs
	for _, excludedFuncName := range m.options.ExcludedFunctions {
		delete(m.collectionSpec.Programs, excludedFuncName)
	}
	for i := 0; i < len(m.Probes); {
		if slices.Contains(m.options.ExcludedFunctions, m.Probes[i].EBPFFuncName) {
			m.Probes = slices.Delete(m.Probes, i, i+1)
		} else {
			i++
		}
	}
	// Remove ConstantEditors that point to only excluded functions
	for i := 0; i < len(m.options.ConstantEditors); {
		ce := m.options.ConstantEditors[i]
		isSpecific := len(ce.ProbeIdentificationPairs) > 0
		// remove excluded ProbeIdentificationPairs
		for j := 0; j < len(ce.ProbeIdentificationPairs); {
			if slices.Contains(m.options.ExcludedFunctions, ce.ProbeIdentificationPairs[j].EBPFFuncName) {
				ce.ProbeIdentificationPairs = slices.Delete(ce.ProbeIdentificationPairs, j, j+1)
			} else {
				j++
			}
		}
		// was a specific constant editor, but all the probes are excluded
		if isSpecific && len(ce.ProbeIdentificationPairs) == 0 {
			m.options.ConstantEditors = slices.Delete(m.options.ConstantEditors, i, i+1)
		} else {
			i++
		}
	}

	// must run before map exclusion in case bypass is disabled
	bypassMap, err := m.setupBypass()
	if err != nil {
		m.stateLock.Unlock()
		return err
	}

	// Remove excluded maps
	for _, excludeMapName := range m.options.ExcludedMaps {
		delete(m.collectionSpec.Maps, excludeMapName)
	}
	for i := 0; i < len(m.Maps); {
		if slices.Contains(m.options.ExcludedMaps, m.Maps[i].Name) {
			m.Maps = slices.Delete(m.Maps, i, i+1)
		} else {
			i++
		}
	}

	// Match Maps and program specs
	if err = m.matchSpecs(); err != nil {
		m.stateLock.Unlock()
		return err
	}

	// Configure activated probes
	m.activateProbes()

	// populate bypass indexes on Probe objects
	// this must run after matchSpecs due to CopyProgram handling
	if bypassMap != nil {
		for _, mProbe := range m.Probes {
			if idx, ok := m.bypassIndexes[mProbe.GetEBPFFuncName()]; ok {
				mProbe.bypassIndex = idx
				mProbe.bypassMap = bypassMap
			}
		}
	}

	m.state = initialized
	m.stateLock.Unlock()
	resetManager := func(m *Manager) {
		m.stateLock.Lock()
		m.state = reset
		m.stateLock.Unlock()
	}

	// newEditor program constants
	if len(options.ConstantEditors) > 0 {
		if err = m.editConstants(); err != nil {
			resetManager(m)
			return err
		}
	}

	// newEditor map spec
	if len(options.MapSpecEditors) > 0 {
		if err = m.editMapSpecs(); err != nil {
			resetManager(m)
			return err
		}
	}

	// Setup map routes
	if len(options.InnerOuterMapSpecs) > 0 {
		for _, ioMapSpec := range options.InnerOuterMapSpecs {
			if err = m.editInnerOuterMapSpec(ioMapSpec); err != nil {
				resetManager(m)
				return err
			}
		}
	}

	// Patch instructions
	for _, patcher := range m.InstructionPatchers {
		if err := patcher(m); err != nil {
			resetManager(m)
			return err
		}
	}

	if options.KernelModuleBTFLoadFunc != nil {
		for _, p := range m.collectionSpec.Programs {
			mod, err := p.KernelModule()
			if err != nil {
				resetManager(m)
				return fmt.Errorf("kernel module search for %s: %w", p.AttachTo, err)
			}
			if mod == "" {
				continue
			}

			if options.VerifierOptions.Programs.KernelModuleTypes == nil {
				options.VerifierOptions.Programs.KernelModuleTypes = make(map[string]*btf.Spec)
			}

			// try default BTF first
			modBTF, err := btf.LoadKernelModuleSpec(mod)
			if err != nil {
				// try callback function next
				modBTF, err = options.KernelModuleBTFLoadFunc(mod)
				if err != nil {
					resetManager(m)
					return fmt.Errorf("kernel module BTF load for %s: %w", mod, err)
				}
			}
			options.VerifierOptions.Programs.KernelModuleTypes[mod] = modBTF
		}
	}

	// Load pinned maps and pinned programs to avoid loading them twice
	if err = m.loadPinnedObjects(); err != nil {
		resetManager(m)
		return err
	}

	// Load eBPF program with the provided verifier options
	if err = m.loadCollection(); err != nil {
		if m.collection != nil {
			m.collection.Close()
		}
		resetManager(m)
		return err
	}
	return nil
}

func (m *Manager) setupBypass() (*Map, error) {
	_, hasBypassMapSpec := m.collectionSpec.Maps[bypassMapName]
	if !hasBypassMapSpec {
		return nil, nil
	}
	if !m.options.BypassEnabled {
		m.options.ExcludedMaps = append(m.options.ExcludedMaps, bypassMapName)
		return nil, nil
	}
	// start with 1, so we know if programs even have a valid index set
	m.maxBypassIndex = 1

	const stackOffset = -8
	// place a limit on how far we will inject from the start of a program
	// otherwise we aren't sure what register we need to save/restore, and it could inflate the number of instructions.
	const maxInstructionOffsetFromProgramStart = 1
	// setup bypass constants for all programs
	m.bypassIndexes = make(map[string]uint32, len(m.collectionSpec.Programs))
	for name, p := range m.collectionSpec.Programs {
		for i := 0; i < len(p.Instructions); i++ {
			ins := p.Instructions[i]
			if ins.Reference() != bypassOptInReference {
				continue
			}
			// return error here to ensure we only error on programs that do have a bypass reference
			if i > maxInstructionOffsetFromProgramStart {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: bypass reference occurs too late in program", name)
			}
			if i > 0 && p.Instructions[i-1].Src != asm.R1 {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: register other than r1 used before injection point", name)
			}

			m.bypassIndexes[name] = m.maxBypassIndex
			newInsns := append([]asm.Instruction{
				asm.Mov.Reg(asm.R6, asm.R1),
				// save bypass index to stack
				asm.StoreImm(asm.RFP, stackOffset, int64(m.maxBypassIndex), asm.Word),
				// store pointer to bypass index
				asm.Mov.Reg(asm.R2, asm.RFP),
				asm.Add.Imm(asm.R2, stackOffset),
				// load map reference
				asm.LoadMapPtr(asm.R1, 0).WithReference(bypassMapName),
				// bpf_map_lookup_elem
				asm.FnMapLookupElem.Call(),
				// if ret == 0, jump to `return 0`
				{
					OpCode:   asm.JEq.Op(asm.ImmSource),
					Dst:      asm.R0,
					Offset:   3, // jump TO return
					Constant: int64(0),
				},
				// pointer indirection of result from map lookup
				asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
				// if bypass NOT enabled, jump over return
				{
					OpCode:   asm.JEq.Op(asm.ImmSource),
					Dst:      asm.R1,
					Offset:   2, // jump over return on next instruction
					Constant: int64(0),
				},
				asm.Return(),
				// zero out used stack slot
				asm.StoreImm(asm.RFP, stackOffset, 0, asm.Word),
				asm.Mov.Reg(asm.R1, asm.R6),
			}, p.Instructions[i+1:]...)
			// necessary to keep kernel happy about source information for start of program
			newInsns[0] = newInsns[0].WithSource(ins.Source())
			p.Instructions = append(p.Instructions[:i], newInsns...)
			m.maxBypassIndex += 1
			break
		}
	}
	// no programs modified
	if m.maxBypassIndex == 1 {
		m.options.ExcludedMaps = append(m.options.ExcludedMaps, bypassMapName)
		return nil, nil
	}

	hasPerCPU := false
	if err := features.HaveMapType(ebpf.PerCPUArray); err == nil {
		hasPerCPU = true
	}

	bypassMap := &Map{Name: bypassMapName}
	m.Maps = append(m.Maps, bypassMap)

	if m.options.MapSpecEditors == nil {
		m.options.MapSpecEditors = make(map[string]MapSpecEditor)
	}
	m.options.MapSpecEditors[bypassMapName] = MapSpecEditor{
		MaxEntries: m.maxBypassIndex + 1,
		EditorFlag: EditMaxEntries,
	}

	if !hasPerCPU {
		// use scalar value for bypass/enable
		bypassValue = 1
		enableValue = 0
		return bypassMap, nil
	}

	// upgrade map type to per-cpu, if available
	specEditor := m.options.MapSpecEditors[bypassMapName]
	specEditor.Type = ebpf.PerCPUArray
	specEditor.EditorFlag |= EditType
	m.options.MapSpecEditors[bypassMapName] = specEditor

	// allocate per-cpu slices used for bypass/enable
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if bypassValue == nil {
		bypassValue = makeAndSet(cpus, uint32(1))
	}
	if enableValue == nil {
		enableValue = makeAndSet(cpus, uint32(0))
	}

	return bypassMap, nil
}

// Start - Attach eBPF programs, start perf ring readers and apply maps and tail calls routing.
func (m *Manager) Start() error {
	m.stateLock.Lock()
	if m.state < initialized {
		m.stateLock.Unlock()
		return ErrManagerNotInitialized
	}
	if m.state >= running {
		m.stateLock.Unlock()
		return nil
	}

	if !m.options.KeepKernelBTF {
		// release kernel BTF. It should no longer be needed
		m.options.VerifierOptions.Programs.KernelTypes = nil
		m.options.VerifierOptions.Programs.KernelModuleTypes = nil
	}

	// clean up tracefs
	if err := m.cleanupTraceFS(); err != nil {
		m.stateLock.Unlock()
		return fmt.Errorf("failed to cleanup tracefs: %w", err)
	}

	// Start perf ring readers
	for _, perfRing := range m.PerfMaps {
		if m.options.SkipPerfMapReaderStartup[perfRing.Name] {
			continue
		}
		if err := perfRing.Start(); err != nil {
			// Clean up
			_ = m.stop(CleanInternal)
			m.stateLock.Unlock()
			return err
		}
	}

	// Start ring buffer readers
	for _, ringBuffer := range m.RingBuffers {
		if m.options.SkipRingbufferReaderStartup[ringBuffer.Name] {
			continue
		}
		if err := ringBuffer.Start(); err != nil {
			// Clean up
			_ = m.stop(CleanInternal)
			m.stateLock.Unlock()
			return err
		}
	}

	// Attach eBPF programs
	for _, probe := range m.Probes {
		// ignore the error, they are already collected per probes and will be surfaced by the
		// activation validators if needed.
		_ = probe.Attach()
	}

	m.state = running
	m.stateLock.Unlock()

	// Check probe selectors
	var validationErrs error
	for _, selector := range m.options.ActivatedProbes {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = errors.Join(validationErrs, err)
		}
	}
	if validationErrs != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return fmt.Errorf("probes activation validation failed: %w", validationErrs)
	}

	// Handle Maps router
	if err := m.UpdateMapRoutes(m.options.MapRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}

	// Handle Program router
	if err := m.UpdateTailCallRoutes(m.options.TailCallRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}
	return nil
}

func (m *Manager) Pause() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state == paused {
		return nil
	}
	if m.state <= initialized {
		return ErrManagerNotStarted
	}
	if !m.options.BypassEnabled {
		return nil
	}

	for _, probe := range m.Probes {
		if err := probe.Pause(); err != nil {
			return err
		}
	}
	m.state = paused
	return nil
}

func (m *Manager) Resume() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state == running {
		return nil
	}
	if m.state <= initialized {
		return ErrManagerNotStarted
	}
	if !m.options.BypassEnabled {
		return nil
	}

	for _, probe := range m.Probes {
		if err := probe.Resume(); err != nil {
			return err
		}
	}
	m.state = running
	return nil
}

// Stop - Detach all eBPF programs and stop perf ring readers. The cleanup parameter defines which maps should be closed.
// See MapCleanupType for mode.
func (m *Manager) Stop(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < initialized {
		return ErrManagerNotInitialized
	}
	return m.stop(cleanup)
}

// StopReaders stop the kernel events readers Perf or Ring buffer
func (m *Manager) StopReaders(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	return m.stopReaders(cleanup)
}

func (m *Manager) stopReaders(cleanup MapCleanupType) error {
	var errs []error

	// Stop perf ring readers
	for _, perfRing := range m.PerfMaps {
		if stopErr := perfRing.Stop(cleanup); stopErr != nil {
			errs = append(errs, fmt.Errorf("perf ring reader %s couldn't gracefully shut down: %w", perfRing.Name, stopErr))
		}
	}

	// Stop ring buffer readers
	for _, ringBuffer := range m.RingBuffers {
		if stopErr := ringBuffer.Stop(cleanup); stopErr != nil {
			errs = append(errs, fmt.Errorf("ring buffer reader %s couldn't gracefully shut down: %w", ringBuffer.Name, stopErr))
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) stop(cleanup MapCleanupType) error {
	var errs []error
	errs = append(errs, m.stopReaders(cleanup))

	// Detach eBPF programs
	for _, probe := range m.Probes {
		if stopErr := probe.Stop(); stopErr != nil {
			errs = append(errs, fmt.Errorf("program %s couldn't gracefully shut down: %w", probe.ProbeIdentificationPair, stopErr))
		}
	}

	// Close maps
	for _, managerMap := range m.Maps {
		if closeErr := managerMap.Close(cleanup); closeErr != nil {
			errs = append(errs, fmt.Errorf("couldn't gracefully close map %s: %w", managerMap.Name, closeErr))
		}
	}

	// Close all netlink sockets
	m.netlinkSocketCache.cleanup()

	// Clean up collection
	// Note: we might end up closing the same programs or maps multiple times but the library gracefully handles those
	// situations. We can't rely only on the collection to close all maps and programs because some pinned objects were
	// removed from the collection.
	m.collection.Close()

	m.state = reset
	return errors.Join(errs...)
}

// NewMap - Create a new map using the provided parameters. The map is added to the list of maps managed by the manager.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewMap(spec *ebpf.MapSpec, options MapOptions) (*ebpf.Map, error) {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.collection == nil || m.state < initialized {
		return nil, ErrManagerNotInitialized
	}

	// check if the name of the new map is available
	_, exists, _ := m.getMap(spec.Name)
	if exists {
		return nil, ErrMapNameInUse
	}

	// Create the new map
	managerMap, err := loadNewMap(spec, options)
	if err != nil {
		return nil, err
	}

	// init map
	if err := managerMap.init(); err != nil {
		// Clean up
		_ = managerMap.Close(CleanInternal)
		return nil, err
	}

	// Add map to the list of maps managed by the manager
	m.Maps = append(m.Maps, managerMap)
	return managerMap.array, nil
}

// CloneMap - Duplicates the spec of an existing map, before creating a new one.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) CloneMap(name string, newName string, options MapOptions) (*ebpf.Map, error) {
	// Select map to clone
	oldSpec, exists, err := m.GetMapSpec(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("failed to clone maps/%s: %w", name, ErrUnknownSection)
	}

	// Duplicate spec and create a new map
	spec := oldSpec.Copy()
	spec.Name = newName
	return m.NewMap(spec, options)
}

// AddHook - Hook an existing program to a hook point. This is particularly useful when you need to trigger an
// existing program on a hook point that is determined at runtime. For example, you might want to hook an existing
// eBPF TC classifier to the newly created interface of a container. Make sure to specify a unique uid in the new probe,
// you will need it if you want to detach the program later. The original program is selected using the provided UID,
// the section and the eBPF function name provided in the new probe.
func (m *Manager) AddHook(UID string, newProbe *Probe) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.collection == nil || m.state < initialized {
		return ErrManagerNotInitialized
	}

	oldID := ProbeIdentificationPair{UID: UID, EBPFFuncName: newProbe.EBPFFuncName}
	// Look for the eBPF program
	progs, found, err := m.getProgram(oldID)
	if err != nil {
		return err
	}
	if !found || len(progs) == 0 {
		return fmt.Errorf("couldn't find program %s: %w", oldID, ErrUnknownSectionOrFuncName)
	}
	prog := progs[0]
	progSpecs, found, _ := m.getProgramSpec(oldID)
	if !found || len(progSpecs) == 0 {
		return fmt.Errorf("couldn't find programSpec %s: %w", oldID, ErrUnknownSectionOrFuncName)
	}
	progSpec := progSpecs[0]

	// Ensure that the new probe is enabled
	newProbe.Enabled = true

	// Make sure the provided identification pair is unique
	_, exists, _ := m.getProgramSpec(newProbe.ProbeIdentificationPair)
	if exists {
		return fmt.Errorf("probe %s already exists: %w", newProbe.ProbeIdentificationPair, ErrIdentificationPairInUse)
	}

	// Clone program
	clonedProg, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("couldn't clone %v: %w", oldID, err)
	}
	newProbe.program = clonedProg
	newProbe.programSpec = progSpec

	var bypassMap *Map
	for _, mp := range m.Maps {
		if mp.Name == bypassMapName {
			bypassMap = mp
			break
		}
	}
	bypassIndex, ok := m.bypassIndexes[newProbe.EBPFFuncName]
	if ok && bypassMap != nil {
		newProbe.bypassIndex = bypassIndex
		newProbe.bypassMap = bypassMap
	}

	// init program
	if err = newProbe.init(m); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to initialize new probe: %w", err)
	}

	// Pin if needed
	if newProbe.PinPath != "" {
		if err = newProbe.program.Pin(newProbe.PinPath); err != nil {
			// clean up
			_ = newProbe.Stop()
			return fmt.Errorf("couldn't pin new probe: %w", err)
		}
	}

	// Attach program
	if err = newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("couldn't attach new probe: %w", err)
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, newProbe)
	return nil
}

// DetachHook - Detach an eBPF program from a hook point. If there is only one instance left of this program in the
// kernel, then the probe will be detached but the program will not be closed (so that it can be used later). In that
// case, calling DetachHook has essentially the same effect as calling Detach() on the right Probe instance. However,
// if there are more than one instance in the kernel of the requested program, then the probe selected by the provided
// ProbeIdentificationPair is detached, and its own handle of the program is closed.
func (m *Manager) DetachHook(id ProbeIdentificationPair) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.collection == nil || m.state < initialized {
		return ErrManagerNotInitialized
	}

	// Check how many instances of the program are left in the kernel
	progs, _, err := m.getProgram(ProbeIdentificationPair{UID: "", EBPFFuncName: id.EBPFFuncName})
	if err != nil {
		return err
	}
	shouldStop := len(progs) > 1

	// Look for the probe
	idToDelete := -1
	for mID, mProbe := range m.Probes {
		if mProbe.ProbeIdentificationPair == id {
			// Detach or stop the probe depending on shouldStop
			if shouldStop {
				if err = mProbe.Stop(); err != nil {
					return fmt.Errorf("couldn't stop probe %s: %w", id, err)
				}
			} else {
				if err = mProbe.Detach(); err != nil {
					return fmt.Errorf("couldn't detach probe %s: %w", id, err)
				}
			}
			idToDelete = mID
		}
	}
	if idToDelete >= 0 {
		m.Probes = slices.Delete(m.Probes, idToDelete, idToDelete+1)
	}
	return nil
}

func (m *Manager) CloneProgram(UID string, newProbe *Probe, constantsEditors []ConstantEditor, mapEditors map[string]*ebpf.Map) error {
	return m.CloneProgramWithSpecEditor(UID, newProbe, constantsEditors, mapEditors, nil)
}

// CloneProgramWithSpecEditor - Create a clone of a program, load it in the kernel and attach it to its hook point. Since the eBPF
// program instructions are copied before the program is loaded, you can edit them with a ConstantEditor, or remap
// the eBPF maps as you like. This is particularly useful to work around the absence of Array of Maps and Hash of Maps:
// first create the new maps you need, then clone the program you're interested in and rewrite it with the new maps,
// using a MapEditor. The original program is selected using the provided UID and the section provided in the new probe.
// Note that the BTF based constant edition will not work with this method.
func (m *Manager) CloneProgramWithSpecEditor(UID string, newProbe *Probe, constantsEditors []ConstantEditor, mapEditors map[string]*ebpf.Map, specEditor func(spec *ebpf.ProgramSpec)) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.collection == nil || m.state < initialized {
		return ErrManagerNotInitialized
	}

	oldID := ProbeIdentificationPair{UID: UID, EBPFFuncName: newProbe.EBPFFuncName}
	var oldProgramSpec *ebpf.ProgramSpec
	// look for an existing probe
	oldProbe, found := m.getProbe(oldID)
	if found {
		// check if the program spec of this probe was removed
		if !oldProbe.KeepProgramSpec {
			return fmt.Errorf("couldn't clone %s: this probe was cleaned up because KeepProgramSpec was disabled", oldID)
		}
		oldProgramSpec = oldProbe.programSpec
	} else {
		// the cloned program might not have a dedicated Probe, fallback to a collectionPec lookup
		progSpecs, found, err := m.getProgramSpec(oldID)
		if err != nil {
			return err
		}
		if !found || len(progSpecs) == 0 {
			return fmt.Errorf("couldn't find programSpec %v: %w", oldID, ErrUnknownSectionOrFuncName)
		}
		oldProgramSpec = progSpecs[0]

		// the program spec was found
		if !m.options.KeepUnmappedProgramSpecs {
			return fmt.Errorf("couldn't clone %s: this probe was cleaned up because KeepUnmappedProgramSpecs was disabled", oldID)
		}
	}

	// Check if the new probe has a unique identification pair
	_, exists, _ := m.getProgram(newProbe.ProbeIdentificationPair)
	if exists {
		return fmt.Errorf("couldn't add probe %v: %w", newProbe.ProbeIdentificationPair, ErrIdentificationPairInUse)
	}

	// Make sure the new probe is activated
	newProbe.Enabled = true

	// Clone the program
	clonedSpec := oldProgramSpec.Copy()
	if specEditor != nil {
		specEditor(clonedSpec)
	}
	newProbe.programSpec = clonedSpec

	// newEditor constants
	for _, editor := range constantsEditors {
		if err := m.editConstant(newProbe.programSpec, editor); err != nil {
			return fmt.Errorf("couldn't edit constant %s: %w", editor.Name, err)
		}
	}

	// Write current maps
	if err := m.rewriteMaps(newProbe.programSpec, m.collection.Maps, false); err != nil {
		return fmt.Errorf("couldn't rewrite maps in %v: %w", newProbe.ProbeIdentificationPair, err)
	}

	// Rewrite with new maps
	if err := m.rewriteMaps(newProbe.programSpec, mapEditors, true); err != nil {
		return fmt.Errorf("couldn't rewrite maps in %v: %w", newProbe.ProbeIdentificationPair, err)
	}

	// init
	if err := newProbe.initWithOptions(m, true, true); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to initialize new probe %v: %w", newProbe.ProbeIdentificationPair, err)
	}

	// Attach new program
	if err := newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to attach new probe %v: %w", newProbe.ProbeIdentificationPair, err)
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, newProbe)
	return nil
}

func (m *Manager) getProbeProgramSpec(funcName string) (*ebpf.ProgramSpec, error) {
	spec, ok := m.collectionSpec.Programs[funcName]
	if !ok {
		return nil, fmt.Errorf("couldn't find program spec for func %s: %w", funcName, ErrUnknownSectionOrFuncName)
	}
	return spec, nil
}

func (m *Manager) getProbeProgram(funcName string) (*ebpf.Program, error) {
	p, ok := m.collection.Programs[funcName]
	if !ok {
		return nil, fmt.Errorf("couldn't find program %s: %w", funcName, ErrUnknownSectionOrFuncName)
	}
	return p, nil
}

// matchSpecs - Match loaded maps and program specs with the maps and programs provided to the manager
func (m *Manager) matchSpecs() error {
	// Match programs
	for _, probe := range m.Probes {
		programSpec, err := m.getProbeProgramSpec(probe.ProbeIdentificationPair.EBPFFuncName)
		if err != nil {
			return err
		}
		if !probe.CopyProgram {
			probe.programSpec = programSpec
		} else {
			probe.programSpec = programSpec.Copy()
			m.collectionSpec.Programs[probe.GetEBPFFuncName()] = probe.programSpec
		}
	}

	// Match maps
	for _, managerMap := range m.Maps {
		spec, ok := m.collectionSpec.Maps[managerMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", managerMap.Name, ErrUnknownSection)
		}
		spec.Contents = managerMap.Contents
		spec.Freeze = managerMap.Freeze
		managerMap.arraySpec = spec
	}

	// Match perfmaps
	for _, perfMap := range m.PerfMaps {
		spec, ok := m.collectionSpec.Maps[perfMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", perfMap.Name, ErrUnknownSection)
		}
		perfMap.arraySpec = spec
	}

	// Match ring buffer
	for _, ringBuffer := range m.RingBuffers {
		spec, ok := m.collectionSpec.Maps[ringBuffer.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", ringBuffer.Name, ErrUnknownSection)
		}
		ringBuffer.arraySpec = spec
	}

	return nil
}

// matchBPFObjects - Match loaded maps and program specs with the maps and programs provided to the manager
func (m *Manager) matchBPFObjects() error {
	// Match programs
	var mappedProgramSpecNames []string
	for _, probe := range m.Probes {
		program, err := m.getProbeProgram(probe.GetEBPFFuncName())
		if err != nil {
			return err
		}
		probe.program = program
		mappedProgramSpecNames = append(mappedProgramSpecNames, probe.ProbeIdentificationPair.EBPFFuncName)
	}

	// cleanup unmapped ProgramSpec now
	if !m.options.KeepUnmappedProgramSpecs {
	collectionSpec:
		for specName, spec := range m.collectionSpec.Programs {
			for _, name := range mappedProgramSpecNames {
				if specName == name {
					continue collectionSpec
				}
			}
			cleanupProgramSpec(spec)
		}
	}

	// Match maps
	for _, managerMap := range m.Maps {
		arr, ok := m.collection.Maps[managerMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", managerMap.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if managerMap.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			continue
		}
		managerMap.array = arr
	}

	// Match perfmaps
	for _, perfMap := range m.PerfMaps {
		arr, ok := m.collection.Maps[perfMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", perfMap.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if perfMap.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			continue
		}
		perfMap.array = arr
	}

	// Match ring buffers
	for _, ringBuffer := range m.RingBuffers {
		arr, ok := m.collection.Maps[ringBuffer.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", ringBuffer.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if ringBuffer.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			continue
		}
		ringBuffer.array = arr
	}

	return nil
}

func (m *Manager) activateProbes() {
	shouldPopulateActivatedProbes := len(m.options.ActivatedProbes) == 0
	for _, mProbe := range m.Probes {
		shouldActivate := shouldPopulateActivatedProbes
		for _, selector := range m.options.ActivatedProbes {
			for _, p := range selector.GetProbesIdentificationPairList() {
				if mProbe.ProbeIdentificationPair == p {
					shouldActivate = true
				}
			}
		}
		mProbe.Enabled = shouldActivate

		if shouldPopulateActivatedProbes {
			// this will ensure that we check that everything has been activated by default when no selectors are provided
			m.options.ActivatedProbes = append(m.options.ActivatedProbes, &ProbeSelector{
				ProbeIdentificationPair: mProbe.ProbeIdentificationPair,
			})
		}
	}
}

// UpdateActivatedProbes - update the list of activated probes
func (m *Manager) UpdateActivatedProbes(selectors []ProbesSelector) error {
	m.stateLock.Lock()
	if m.state < initialized {
		m.stateLock.Unlock()
		return ErrManagerNotInitialized
	}

	currentProbes := make(map[ProbeIdentificationPair]*Probe)
	for _, p := range m.Probes {
		pip := ProbeIdentificationPair{UID: p.ProbeIdentificationPair.UID, EBPFFuncName: p.ProbeIdentificationPair.EBPFFuncName}
		if p.Enabled {
			currentProbes[pip] = p
		}
	}

	nextProbes := make(map[ProbeIdentificationPair]bool)
	for _, selector := range selectors {
		for _, id := range selector.GetProbesIdentificationPairList() {
			if !slices.Contains(m.options.ExcludedFunctions, id.EBPFFuncName) {
				pip := ProbeIdentificationPair{UID: id.UID, EBPFFuncName: id.EBPFFuncName}
				nextProbes[pip] = true
			}
		}
	}

	for id := range nextProbes {
		var probe *Probe
		if currentProbe, alreadyPresent := currentProbes[id]; alreadyPresent {
			delete(currentProbes, id)
			probe = currentProbe
		} else {
			var found bool
			probe, found = m.getProbe(id)
			if !found {
				m.stateLock.Unlock()
				return fmt.Errorf("couldn't find program %s: %w", id, ErrUnknownSectionOrFuncName)
			}
			probe.Enabled = true
		}
		if !probe.IsRunning() {
			// ignore all errors, they are already collected per probe and will be surfaced by the
			// activation validators if needed.
			_ = probe.init(m)
			_ = probe.Attach()
		}
	}

	for _, probe := range currentProbes {
		if err := probe.Detach(); err != nil {
			m.stateLock.Unlock()
			return err
		}
		probe.Enabled = false
	}

	// update activated probes & check activation
	m.options.ActivatedProbes = selectors

	m.stateLock.Unlock()

	var validationErrs error
	for _, selector := range selectors {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = errors.Join(validationErrs, err)
		}
	}

	if validationErrs != nil {
		// Clean up
		_ = m.stop(CleanInternal)
		return fmt.Errorf("probes activation validation failed: %w", validationErrs)
	}

	return nil
}

// rewriteMaps - Rewrite the provided program spec with the provided maps. failOnError controls if an error should be
// returned when a map couldn't be rewritten.
func (m *Manager) rewriteMaps(program *ebpf.ProgramSpec, eBPFMaps map[string]*ebpf.Map, failOnError bool) error {
	for symbol, eBPFMap := range eBPFMaps {
		err := program.Instructions.AssociateMap(symbol, eBPFMap)
		if err != nil && failOnError {
			return fmt.Errorf("couldn't rewrite map %s: %w", symbol, err)
		}
	}
	return nil
}

// loadCollection - Load the eBPF maps and programs in the CollectionSpec. Programs and Maps are pinned when requested.
func (m *Manager) loadCollection() error {
	var err error

	opts := m.options.VerifierOptions
	// map references replaced this way will get a cloned reference to the *ebpf.Map upon collection load
	opts.MapReplacements = maps.Clone(m.options.MapEditors)
	for name := range opts.MapReplacements {
		if _, ok := m.collectionSpec.Maps[name]; !ok && m.options.MapEditorsIgnoreMissingMaps {
			// prevent error for missing map by removing the editor
			delete(opts.MapReplacements, name)
		}
	}

	m.collection, err = ebpf.NewCollectionWithOptions(m.collectionSpec, opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// include error twice to preserve context, and still allow unwrapping if desired
			return fmt.Errorf("verifier error loading eBPF programs: %w\n%+v", err, ve)
		}
		return fmt.Errorf("couldn't load eBPF programs: %w", err)
	}

	// match loaded bpf objects
	if err = m.matchBPFObjects(); err != nil {
		return fmt.Errorf("couldn't match bpf objects: %w", err)
	}

	// Initialize Maps
	for _, managerMap := range m.Maps {
		if err := managerMap.init(); err != nil {
			return err
		}
	}

	// Initialize PerfMaps
	for _, perfMap := range m.PerfMaps {
		if err := perfMap.init(m); err != nil {
			return err
		}
	}

	// Initialize ring buffers
	for _, ringBuffer := range m.RingBuffers {
		if err := ringBuffer.init(m); err != nil {
			return err
		}
	}

	// Initialize Probes
	for _, probe := range m.Probes {
		// Find program
		if err := probe.init(m); err != nil {
			return err
		}
	}
	return nil
}

// loadPinnedObjects - Loads pinned programs and maps from the bpf virtual file system. If a map is found, the
// CollectionSpec will be edited so that references to that map point to the pinned one. If a program is found, it will
// be detached from the CollectionSpec to avoid loading it twice.
func (m *Manager) loadPinnedObjects() error {
	// Look for pinned maps
	for _, managerMap := range m.Maps {
		if managerMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(managerMap); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned perf buffer
	for _, perfMap := range m.PerfMaps {
		if perfMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(&perfMap.Map); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned perf buffer
	for _, ringBuffer := range m.RingBuffers {
		if ringBuffer.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(&ringBuffer.Map); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned programs
	for _, prog := range m.Probes {
		if prog.PinPath == "" {
			continue
		}
		if err := m.loadPinnedProgram(prog); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

// loadPinnedMap - Loads a pinned map
func (m *Manager) loadPinnedMap(managerMap *Map) error {
	// Check if the pinned object exists
	if _, err := os.Stat(managerMap.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	pinnedMap, err := ebpf.LoadPinnedMap(managerMap.PinPath, nil)
	if err != nil {
		return fmt.Errorf("couldn't load map %s from %s: %w", managerMap.Name, managerMap.PinPath, err)
	}

	m.options.MapEditors[managerMap.Name] = pinnedMap
	managerMap.array = pinnedMap
	return nil
}

// loadPinnedProgram - Loads a pinned program
func (m *Manager) loadPinnedProgram(prog *Probe) error {
	// Check if the pinned object exists
	if _, err := os.Stat(prog.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	pinnedProg, err := ebpf.LoadPinnedProgram(prog.PinPath, nil)
	if err != nil {
		return fmt.Errorf("couldn't load program %v from %s: %w", prog.ProbeIdentificationPair, prog.PinPath, err)
	}
	prog.program = pinnedProg

	// Detach program from CollectionSpec
	delete(m.collectionSpec.Programs, prog.GetEBPFFuncName())
	return nil
}

// sanityCheck - Checks that the probes and maps of the manager were properly defined
func (m *Manager) sanityCheck() error {
	// Check if map names are unique
	cache := map[string]bool{}
	for _, managerMap := range m.Maps {
		_, ok := cache[managerMap.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", managerMap.Name, ErrMapNameInUse)
		}
		cache[managerMap.Name] = true
	}

	for _, perfMap := range m.PerfMaps {
		_, ok := cache[perfMap.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", perfMap.Name, ErrMapNameInUse)
		}
		cache[perfMap.Name] = true
	}

	for _, ringBuffer := range m.RingBuffers {
		_, ok := cache[ringBuffer.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", ringBuffer.Name, ErrMapNameInUse)
		}
		cache[ringBuffer.Name] = true
	}

	// Check if probes identification pairs are unique, request the usage of CloneProbe otherwise
	cache = map[string]bool{}
	for _, managerProbe := range m.Probes {
		_, ok := cache[managerProbe.ProbeIdentificationPair.String()]
		if ok {
			return fmt.Errorf("%v failed the sanity check: %w", managerProbe.ProbeIdentificationPair, ErrCloneProbeRequired)
		}
		cache[managerProbe.ProbeIdentificationPair.String()] = true
	}
	return nil
}
