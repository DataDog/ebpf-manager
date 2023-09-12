package manager

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// MapCleanupType - The map clean up type defines how the maps of a manager should be cleaned up on exit.
//
// A map can only be in one of the following categories
//
//	             ----------------------
//	            |   Internally loaded  |
//	             ----------------------
//	Categories: |  Pinned | Not Pinned |
//	             ----------------------
type MapCleanupType int

const (
	CleanInternalPinned    MapCleanupType = 1 << 1
	CleanInternalNotPinned MapCleanupType = 1 << 2
	CleanInternal                         = CleanInternalPinned | CleanInternalNotPinned
	CleanAll                              = CleanInternal
)

// MapOptions - Generic Map options that are not shared with the MapSpec definition
type MapOptions struct {
	// PinPath - Once loaded, the eBPF map will be pinned to this path. If the map has already been pinned and is
	// already present in the kernel, then it will be loaded from this path.
	PinPath string

	// AlwaysCleanup - Overrides the cleanup type given to the manager. See CleanupType for more.
	AlwaysCleanup bool
}

type Map struct {
	array     *ebpf.Map
	arraySpec *ebpf.MapSpec
	state     state
	stateLock sync.Mutex

	// Name - Name of the map as defined in its section SEC("maps/[name]")
	Name string

	// Contents - The initial contents of the map. May be nil.
	Contents []ebpf.MapKV

	// Freeze - Whether to freeze a map after setting its initial contents.
	Freeze bool

	// Other options
	MapOptions
}

// loadNewMap - Creates a new map instance, loads it and returns a pointer to the Map structure
func loadNewMap(spec *ebpf.MapSpec, options MapOptions) (*Map, error) {
	// Create new map
	managerMap := Map{
		arraySpec:  spec,
		Name:       spec.Name,
		Contents:   spec.Contents,
		Freeze:     spec.Freeze,
		MapOptions: options,
	}

	// Load map
	var err error
	if managerMap.array, err = ebpf.NewMap(spec); err != nil {
		return nil, err
	}

	// Pin map if need be
	if managerMap.PinPath != "" {
		if err = managerMap.array.Pin(managerMap.PinPath); err != nil {
			return nil, fmt.Errorf("couldn't pin map %s at %s: %w", managerMap.Name, managerMap.PinPath, err)
		}
	}
	return &managerMap, nil
}

// init - Initialize a map
func (m *Map) init() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state >= initialized {
		return ErrMapInitialized
	}

	m.state = initialized
	return nil
}

// Close - Close underlying eBPF map.
func (m *Map) Close(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < initialized {
		return ErrMapInitialized
	}
	return m.close(cleanup)
}

// close - (not thread safe) close
func (m *Map) close(cleanup MapCleanupType) error {
	shouldClose := false
	if m.AlwaysCleanup {
		shouldClose = true
	}
	if cleanup&CleanInternalPinned == CleanInternalPinned && m.array.IsPinned() {
		shouldClose = true
	}
	if cleanup&CleanInternalNotPinned == CleanInternalNotPinned && !m.array.IsPinned() {
		shouldClose = true
	}
	if shouldClose {
		err := errors.Join(m.array.Unpin(), m.array.Close())
		if err != nil {
			return err
		}
		m.reset()
	}
	return nil
}

// reset - Cleans up the internal fields of the map
func (m *Map) reset() {
	m.array = nil
	m.arraySpec = nil
	m.state = reset
}
