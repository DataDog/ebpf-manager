package manager

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	tcxTestFunc = "tcx_test"
	tcActUnspec = -1
)

func tcxTestProgramSpec() *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:        tcxTestFunc,
		Type:        ebpf.SchedCLS,
		SectionName: "classifier/" + tcxTestFunc,
		License:     "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, tcActUnspec),
			asm.Return(),
		},
	}
}

func requireTCX(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	prog, err := ebpf.NewProgram(tcxTestProgramSpec())
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	// no interface has this ifindex, so the attach fails, with ErrNotSupported if the kernel lacks TCX
	if _, err = link.AttachTCX(link.TCXOptions{Interface: int(^uint32(0)), Program: prog, Attach: ebpf.AttachTCXIngress}); errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("TCX is unavailable")
	}
}

// newTCTestManager returns a running manager that clones the test classifier
func newTCTestManager(t *testing.T) *Manager {
	t.Helper()
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{tcxTestFunc: tcxTestProgramSpec()}}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		collectionSpec:     spec,
		collection:         coll,
		netlinkSocketCache: newNetlinkSocketCache(),
		options:            Options{KeepUnmappedProgramSpecs: true},
		state:              running,
	}
	t.Cleanup(func() { _ = m.Stop(CleanAll) })
	return m
}

type testNetns struct {
	handle netns.NsHandle
	id     uint32
	nl     *netlink.Handle
}

// newTestNetns creates a network namespace, without moving the test into it
func newTestNetns(t *testing.T) *testNetns {
	t.Helper()
	handle := netns.None()
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origin, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- err
			return
		}
		defer origin.Close()

		handle, err = netns.New()
		if restoreErr := netns.Set(origin); restoreErr != nil {
			errCh <- errors.Join(err, restoreErr)
			return
		}
		runtime.UnlockOSThread()
		errCh <- err
	}()
	if err := <-errCh; err != nil {
		t.Fatalf("couldn't create a network namespace: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	var stat unix.Stat_t
	if err := unix.Fstat(int(handle), &stat); err != nil {
		t.Fatal(err)
	}
	nl, err := netlink.NewHandleAt(handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nl.Close)
	return &testNetns{handle: handle, id: uint32(stat.Ino), nl: nl}
}

func dummy(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func (ns *testNetns) addLink(t *testing.T, l netlink.Link) netlink.Link {
	t.Helper()
	if err := ns.nl.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	added, err := ns.nl.LinkByName(l.Attrs().Name)
	if err != nil {
		t.Fatal(err)
	}
	return added
}

func (ns *testNetns) newProbe(uid string, ifindex int, dir TrafficType, mode TCAttachMode, anchor TCXAnchor) *Probe {
	return &Probe{
		ProbeIdentificationPair: ProbeIdentificationPair{UID: uid, EBPFFuncName: tcxTestFunc},
		IfIndex:                 ifindex,
		IfIndexNetns:            uint64(ns.handle),
		IfIndexNetnsID:          ns.id,
		NetworkDirection:        dir,
		TCAttachMode:            mode,
		TCXAnchor:               anchor,
		// clones of the empty UID copy the spec of an existing clone of the same function
		KeepProgramSpec: true,
	}
}

func (ns *testNetns) cloneTCX(t *testing.T, m *Manager, uid string, ifindex int, dir TrafficType, anchor TCXAnchor) *Probe {
	t.Helper()
	p := ns.newProbe(uid, ifindex, dir, TCAttachModeTCX, anchor)
	if err := m.CloneProgram("", p, nil, nil); err != nil {
		t.Fatal(err)
	}
	return p
}

// tcxPrograms returns the programs of a TCX hook, in their run order
func (ns *testNetns) tcxPrograms(t *testing.T, ifindex int, dir TrafficType) []link.AttachedProgram {
	t.Helper()
	var res *link.QueryResult
	err := runInNetns(ns.handle, func() (err error) {
		res, err = link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: (&Probe{NetworkDirection: dir}).tcxAttachType()})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Programs
}

func (ns *testNetns) requirePrograms(t *testing.T, ifindex int, dir TrafficType, want ...ebpf.ProgramID) {
	t.Helper()
	var got []ebpf.ProgramID
	for _, prog := range ns.tcxPrograms(t, ifindex, dir) {
		got = append(got, prog.ID)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s programs of interface %d: got %v, want %v", dir, ifindex, got, want)
	}
}

// attachForeignTCX attaches a classifier that the manager doesn't know about, and returns its ID
func (ns *testNetns) attachForeignTCX(t *testing.T, ifindex int, anchor link.Anchor) ebpf.ProgramID {
	t.Helper()
	prog, err := ebpf.NewProgram(tcxTestProgramSpec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	var l link.Link
	err = runInNetns(ns.handle, func() (err error) {
		l, err = link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: ebpf.AttachTCXIngress, Anchor: anchor})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return id
}

func probeID(p *Probe) ebpf.ProgramID {
	return ebpf.ProgramID(p.ID())
}

func TestTCXAttachDetach(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index

	ingress := ns.cloneTCX(t, m, "ingress", ifindex, Ingress, TCXAnchorHead)
	egress := ns.cloneTCX(t, m, "egress", ifindex, Egress, TCXAnchorHead)
	ns.requirePrograms(t, ifindex, Ingress, probeID(ingress))
	ns.requirePrograms(t, ifindex, Egress, probeID(egress))
	if !ingress.IsTCFilterActive() || !egress.IsTCFilterActive() {
		t.Fatal("attached probes should be active")
	}

	// DetachHook stops a probe while another clone of its program is left, and only detaches the last one
	if err := m.DetachHook(ingress.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress)
	ns.requirePrograms(t, ifindex, Egress, probeID(egress))
	if err := m.DetachHook(egress.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Egress)
}

func TestTCXAnchors(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index

	first := ns.cloneTCX(t, m, "first", ifindex, Ingress, TCXAnchorHead)
	second := ns.cloneTCX(t, m, "second", ifindex, Ingress, TCXAnchorHead)
	tail := ns.cloneTCX(t, m, "tail", ifindex, Ingress, TCXAnchorTail)
	ns.requirePrograms(t, ifindex, Ingress, probeID(second), probeID(first), probeID(tail))
}

func TestTCXForeignProgram(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index
	foreignID := ns.attachForeignTCX(t, ifindex, link.Tail())

	p := ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)
	ns.requirePrograms(t, ifindex, Ingress, probeID(p), foreignID)
	if !p.IsTCFilterActive() {
		t.Error("a probe should be active next to foreign programs")
	}
	if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress, foreignID)

	ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)
	if err := m.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress, foreignID)
}

func TestTCXStop(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	stopped, kept := newTestNetns(t), newTestNetns(t)
	ifindexes := make(map[*testNetns]int)
	for _, ns := range []*testNetns{stopped, kept} {
		ifindexes[ns] = ns.addLink(t, dummy("dummy0")).Attrs().Index
		ns.cloneTCX(t, m, fmt.Sprintf("probe_%d", ns.id), ifindexes[ns], Ingress, TCXAnchorHead)
	}

	if err := m.CleanupNetworkNamespace(stopped.id); err != nil {
		t.Fatal(err)
	}
	stopped.requirePrograms(t, ifindexes[stopped], Ingress)
	if len(kept.tcxPrograms(t, ifindexes[kept], Ingress)) != 1 {
		t.Fatal("CleanupNetworkNamespace should only stop the probes of its namespace")
	}
	if _, ok := m.netlinkSocketCache.lookup(stopped.id); ok {
		t.Error("CleanupNetworkNamespace should drop the netlink socket of its namespace")
	}

	if err := m.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	kept.requirePrograms(t, ifindexes[kept], Ingress)
}

func TestTCXIsTCFilterActive(t *testing.T) {
	requireTCX(t)

	t.Run("deleted interface", func(t *testing.T) {
		m := newTCTestManager(t)
		ns := newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)
		if err := ns.nl.LinkDel(dev); err != nil {
			t.Fatal(err)
		}
		if p.IsTCFilterActive() {
			t.Error("a probe whose interface is deleted should be inactive")
		}
	})

	t.Run("moved interface", func(t *testing.T) {
		m := newTCTestManager(t)
		ns, other := newTestNetns(t), newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		ifindex := dev.Attrs().Index
		p := ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)

		// the interface keeps its ifindex in the other namespace, and the link follows it
		if err := ns.nl.LinkSetNsFd(dev, int(other.handle)); err != nil {
			t.Fatal(err)
		}
		other.requirePrograms(t, ifindex, Ingress, probeID(p))
		if p.IsTCFilterActive() {
			t.Error("a probe whose interface left its namespace should be inactive")
		}
		ns.addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "reused", Index: ifindex}})
		if p.IsTCFilterActive() {
			t.Error("a probe whose ifindex was taken by another interface should be inactive")
		}

		if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
			t.Fatal(err)
		}
		other.requirePrograms(t, ifindex, Ingress)
	})
}

func TestTCXLinkIfIndex(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns, other := newTestNetns(t), newTestNetns(t)
	dev := ns.addLink(t, dummy("dummy0"))
	// the interface gets a new ifindex in a namespace where its ifindex is taken
	other.addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "taken", Index: dev.Attrs().Index}})
	p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)

	requireIfIndex := func(want int) {
		t.Helper()
		if ifindex, err := p.TCXLinkIfIndex(); err != nil || int(ifindex) != want {
			t.Fatalf("got ifindex %d and error %v, want %d", ifindex, err, want)
		}
	}
	requireIfIndex(dev.Attrs().Index)
	if err := ns.nl.LinkSetNsFd(dev, int(other.handle)); err != nil {
		t.Fatal(err)
	}
	moved, err := other.nl.LinkByName("dummy0")
	if err != nil {
		t.Fatal(err)
	}
	requireIfIndex(moved.Attrs().Index)
	if err = other.nl.LinkDel(moved); err != nil {
		t.Fatal(err)
	}
	requireIfIndex(0)
}

func TestTCXReattachWithClosedHandle(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index
	handle, err := unix.FcntlInt(uintptr(ns.handle), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := ns.newProbe("probe", ifindex, Ingress, TCAttachModeTCX, TCXAnchorHead)
	p.IfIndexNetns = uint64(handle)
	if err = m.CloneProgram("", p, nil, nil); err != nil {
		t.Fatal(err)
	}

	// like the callers of CloneProgram, close the handle once attached: its number can then point to any file
	_ = unix.Close(handle)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	if err = p.Detach(); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress)
	// UpdateActivatedProbes attaches the selected probes that aren't running
	if err = m.UpdateActivatedProbes([]ProbesSelector{&ProbeSelector{ProbeIdentificationPair: p.ProbeIdentificationPair}}); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress, probeID(p))
}

func TestTCXAttachErrors(t *testing.T) {
	requireTCX(t)

	t.Run("interface missing before the attach", func(t *testing.T) {
		m := newTCTestManager(t)
		ns := newTestNetns(t)
		err := m.CloneProgram("", ns.newProbe("probe", missingIfIndex, Ingress, TCAttachModeTCX, TCXAnchorHead), nil, nil)
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			t.Fatalf("got %v, want a netlink.LinkNotFoundError", err)
		}
	})

	t.Run("interface gone during the attach", func(t *testing.T) {
		m := newTCTestManager(t)
		ns := newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		p := ns.newProbe("probe", dev.Attrs().Index, Ingress, TCAttachModeTCX, TCXAnchorHead)
		p.Enabled = true
		p.programSpec = tcxTestProgramSpec()
		if err := p.initWithOptions(m, true, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Stop() })

		// the probe keeps the interface it resolves, so that only the attach itself sees it gone
		if _, err := p.ResolveLink(); err != nil {
			t.Fatal(err)
		}
		if err := ns.nl.LinkDel(dev); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); !errors.Is(err, unix.ENODEV) {
			t.Fatalf("got %v, want %v", err, unix.ENODEV)
		}
	})

	t.Run("namespace switch failure", func(t *testing.T) {
		m := newTCTestManager(t)
		ns := newTestNetns(t)
		ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index
		sock, err := NewNetlinkSocket(uint64(ns.handle))
		if err != nil {
			t.Fatal(err)
		}
		m.netlinkSocketCache.cache[ns.id] = sock
		// setns rejects a handle copy that isn't a namespace with EINVAL
		if sock.tcxNetns, err = os.Open(os.DevNull); err != nil {
			t.Fatal(err)
		}

		err = m.CloneProgram("", ns.newProbe("probe", ifindex, Ingress, TCAttachModeTCX, TCXAnchorHead), nil, nil)
		if !errors.Is(err, ErrNetnsSwitch) || !errors.Is(err, unix.EINVAL) {
			t.Fatalf("got %v, want %v wrapping %v", err, ErrNetnsSwitch, unix.EINVAL)
		}
		ns.requirePrograms(t, ifindex, Ingress)
	})
}
