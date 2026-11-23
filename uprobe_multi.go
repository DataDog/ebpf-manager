package manager

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

const uprobeMultiSuffix = "_uprobe_multi"

// UprobeMultiStatus reports the selected backend and why an optional multi
// load fell back. An empty UprobeMultiPrograms option returns false, nil.
func (m *Manager) UprobeMultiStatus() (enabled bool, fallback error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.uprobeMultiEnabled, m.uprobeMultiError
}

// loadUprobeMultiCollection runs after all instruction/map editors and before
// any probes or readers start. Failed collection loads release their own
// partial resources, so fallback can load the untouched legacy specification.
func (m *Manager) loadUprobeMultiCollection(opts ebpf.CollectionOptions) (*ebpf.Collection, error) {
	m.uprobeMultiEnabled, m.uprobeMultiError = false, nil
	if len(m.options.UprobeMultiPrograms) != 0 {
		m.uprobeMultiError = features.HaveBPFLinkUprobeMulti()
		if m.uprobeMultiError == nil {
			var spec *ebpf.CollectionSpec
			var routes []TailCallRoute
			spec, routes, m.uprobeMultiError = prepareUprobeMulti(m.collectionSpec, m.options.UprobeMultiPrograms, m.options.TailCallRouter)
			if m.uprobeMultiError == nil {
				var collection *ebpf.Collection
				collection, m.uprobeMultiError = ebpf.NewCollectionWithOptions(spec, opts)
				if m.uprobeMultiError == nil {
					// Populate private routes before AddHook or Start can execute
					// multi programs. Original routes still serve legacy callers.
					for _, route := range routes {
						if err := collection.Maps[route.ProgArrayName].Update(route.Key, collection.Programs[route.ProbeIdentificationPair.EBPFFuncName], ebpf.UpdateAny); err != nil {
							m.uprobeMultiError = fmt.Errorf("populate multi-uprobe routes: %w", err)
							break
						}
					}
					if m.uprobeMultiError == nil {
						m.collectionSpec = spec
						// matchSpecs already resolved CopyProgram during initState.
						// Rebind without making those copies a second time.
						for _, probe := range m.Probes {
							probe.programSpec = spec.Programs[probe.GetEBPFFuncName()]
						}
						m.options.TailCallRouter = append(m.options.TailCallRouter, routes...)
						m.uprobeMultiEnabled = true
						return collection, nil
					}
					collection.Close()
				}
			}
		}
	}
	return ebpf.NewCollectionWithOptions(m.collectionSpec, opts)
}

// prepareUprobeMulti replaces only the selected application roots. Legacy
// kernel probes can also reach the original tail-call arrays, so those arrays
// and their targets must remain available with their original attach types.
func prepareUprobeMulti(original *ebpf.CollectionSpec, roots []string, routes []TailCallRoute) (*ebpf.CollectionSpec, []TailCallRoute, error) {
	spec := original.Copy()
	rootSet := make(map[string]bool, len(roots))
	for _, name := range roots {
		p := original.Programs[name]
		if p == nil || p.Type != ebpf.Kprobe || (!strings.HasPrefix(p.SectionName, "uprobe/") && !strings.HasPrefix(p.SectionName, "uretprobe/")) {
			return nil, nil, fmt.Errorf("invalid multi-uprobe root %s", name)
		}
		rootSet[name] = true
	}
	for _, route := range routes {
		if rootSet[route.ProbeIdentificationPair.EBPFFuncName] {
			return nil, nil, fmt.Errorf("multi-uprobe root is also a shared tail-call target: %s", route.ProbeIdentificationPair.EBPFFuncName)
		}
	}
	programName := func(name string) string {
		if rootSet[name] {
			return name
		}
		return name + uprobeMultiSuffix
	}
	queue := append([]string(nil), roots...)
	seenPrograms, seenMaps := map[string]bool{}, map[string]bool{}
	var multiRoutes []TailCallRoute
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seenPrograms[name] {
			continue
		}
		seenPrograms[name] = true
		originalProgram := original.Programs[name]
		if originalProgram == nil || originalProgram.Type != ebpf.Kprobe {
			return nil, nil, fmt.Errorf("missing or incompatible multi-uprobe program %s", name)
		}
		newName := programName(name)
		if !rootSet[name] && original.Programs[newName] != nil {
			return nil, nil, fmt.Errorf("multi-uprobe program name collision: %s", newName)
		}
		program := originalProgram.Copy()
		program.AttachType = ebpf.AttachTraceUprobeMulti
		spec.Programs[newName] = program
		for i, ins := range program.Instructions {
			ref := ins.Reference()
			mapSpec := original.Maps[ref]
			if mapSpec == nil || mapSpec.Type != ebpf.ProgramArray {
				continue
			}
			mapName := ref + uprobeMultiSuffix
			program.Instructions[i] = ins.WithReference(mapName)
			if seenMaps[ref] {
				continue
			}
			seenMaps[ref] = true
			if original.Maps[mapName] != nil {
				return nil, nil, fmt.Errorf("multi-uprobe map name collision: %s", mapName)
			}
			private := mapSpec.Copy()
			private.Contents, private.Pinning = nil, ebpf.PinNone
			spec.Maps[mapName] = private
			for _, route := range routes {
				if route.ProgArrayName != ref {
					continue
				}
				if route.Program != nil {
					return nil, nil, fmt.Errorf("cannot convert external tail-call program in %s", ref)
				}
				queue = append(queue, route.ProbeIdentificationPair.EBPFFuncName)
				route.ProgArrayName = mapName
				route.ProbeIdentificationPair = ProbeIdentificationPair{EBPFFuncName: programName(route.ProbeIdentificationPair.EBPFFuncName)}
				multiRoutes = append(multiRoutes, route)
			}
		}
	}
	return spec, multiRoutes, nil
}
