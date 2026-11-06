package manager

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
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

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func requireTCX(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if err := HaveTCX(); err != nil {
		t.Skipf("TCX is unavailable: %v", err)
	}
}

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
	err := runInNetns(ns.handle, func() error {
		var err error
		res, err = link.QueryPrograms(link.QueryOptions{
			Target: ifindex,
			Attach: (&Probe{NetworkDirection: dir}).tcxAttachType(),
		})
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

// attachForeignTCX attaches a classifier that the manager doesn't know about
func (ns *testNetns) attachForeignTCX(t *testing.T, ifindex int, anchor link.Anchor) (ebpf.ProgramID, link.Link) {
	t.Helper()
	prog, err := ebpf.NewProgram(tcxTestProgramSpec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	var l link.Link
	err = runInNetns(ns.handle, func() error {
		var err error
		l, err = link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: ebpf.AttachTCXIngress, Anchor: anchor})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return programID(t, prog), l
}

func programID(t *testing.T, prog *ebpf.Program) ebpf.ProgramID {
	t.Helper()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("program ID unavailable")
	}
	return id
}

func probeID(p *Probe) ebpf.ProgramID {
	return ebpf.ProgramID(p.ID())
}

func linkID(t *testing.T, p *Probe) link.ID {
	t.Helper()
	l, ok := p.progLink.(link.Link)
	if !ok {
		t.Fatalf("%s has no TCX link", p.ProbeIdentificationPair)
	}
	info, err := l.Info()
	if err != nil {
		t.Fatal(err)
	}
	return info.ID
}

func TestHaveTCX(t *testing.T) {
	requireRoot(t)
	ns := newTestNetns(t)
	ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index
	prog, err := ebpf.NewProgram(tcxTestProgramSpec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	attachErr := runInNetns(ns.handle, func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			return err
		}
		return l.Close()
	})
	if haveErr := HaveTCX(); (haveErr == nil) != (attachErr == nil) {
		t.Fatalf("HaveTCX returned %v, but attaching a TCX link returned %v", haveErr, attachErr)
	}
}

func TestTCXAttachDetach(t *testing.T) {
	requireTCX(t)
	for name, newDev := range map[string]netlink.Link{
		"dummy": dummy("dummy0"),
		"veth":  &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}, PeerName: "veth1"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newTCTestManager(t)
			ns := newTestNetns(t)
			dev := ns.addLink(t, newDev)
			ifindex := dev.Attrs().Index

			ingress := ns.cloneTCX(t, m, "ingress", ifindex, Ingress, TCXAnchorHead)
			egress := ns.cloneTCX(t, m, "egress", ifindex, Egress, TCXAnchorHead)
			ns.requirePrograms(t, ifindex, Ingress, probeID(ingress))
			ns.requirePrograms(t, ifindex, Egress, probeID(egress))
			if id, _ := ns.tcxPrograms(t, ifindex, Ingress)[0].LinkID(); id != linkID(t, ingress) {
				t.Errorf("the ingress hook holds link %d instead of %d", id, linkID(t, ingress))
			}
			if !ingress.IsTCFilterActive() || !egress.IsTCFilterActive() {
				t.Fatal("attached probes should be active")
			}

			qdiscs, err := ns.nl.QdiscList(dev)
			if err != nil {
				t.Fatal(err)
			}
			for _, qdisc := range qdiscs {
				if qdisc.Type() == "clsact" {
					t.Error("TCX attaches shouldn't add a clsact qdisc")
				}
			}

			// DetachHook stops a probe while another clone of its program is left, and only detaches the last one
			if err = m.DetachHook(ingress.ProbeIdentificationPair); err != nil {
				t.Fatal(err)
			}
			ns.requirePrograms(t, ifindex, Ingress)
			ns.requirePrograms(t, ifindex, Egress, probeID(egress))
			if err = m.DetachHook(egress.ProbeIdentificationPair); err != nil {
				t.Fatal(err)
			}
			ns.requirePrograms(t, ifindex, Egress)
		})
	}
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
	foreignID, foreignLink := ns.attachForeignTCX(t, ifindex, link.Tail())

	p := ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)
	ns.requirePrograms(t, ifindex, Ingress, probeID(p), foreignID)

	if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress, foreignID)

	ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)
	if err := m.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	ns.requirePrograms(t, ifindex, Ingress, foreignID)
	if info, err := foreignLink.Info(); err != nil || info.TCX() == nil || int(info.TCX().Ifindex) != ifindex {
		t.Errorf("the foreign link should still be attached to interface %d: %+v, %v", ifindex, info, err)
	}
}

func TestTCXStop(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	stopped, kept := newTestNetns(t), newTestNetns(t)
	for _, ns := range []*testNetns{stopped, kept} {
		ifindex := ns.addLink(t, dummy("dummy0")).Attrs().Index
		ns.cloneTCX(t, m, fmt.Sprintf("ingress_%d", ns.id), ifindex, Ingress, TCXAnchorHead)
		ns.cloneTCX(t, m, fmt.Sprintf("egress_%d", ns.id), ifindex, Egress, TCXAnchorHead)
	}
	ifindex := func(ns *testNetns) int {
		dev, err := ns.nl.LinkByName("dummy0")
		if err != nil {
			t.Fatal(err)
		}
		return dev.Attrs().Index
	}

	if err := m.CleanupNetworkNamespace(stopped.id); err != nil {
		t.Fatal(err)
	}
	stopped.requirePrograms(t, ifindex(stopped), Ingress)
	stopped.requirePrograms(t, ifindex(stopped), Egress)
	if len(kept.tcxPrograms(t, ifindex(kept), Ingress)) != 1 || len(kept.tcxPrograms(t, ifindex(kept), Egress)) != 1 {
		t.Fatal("CleanupNetworkNamespace should only stop the probes of its namespace")
	}
	if _, ok := m.netlinkSocketCache.lookup(stopped.id); ok {
		t.Error("CleanupNetworkNamespace should drop the netlink socket of its namespace")
	}

	if err := m.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	kept.requirePrograms(t, ifindex(kept), Ingress)
	kept.requirePrograms(t, ifindex(kept), Egress)
}

func TestTCXIsTCFilterActive(t *testing.T) {
	requireTCX(t)

	t.Run("deleted interface", func(t *testing.T) {
		m := newTCTestManager(t)
		ns := newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)
		if !p.IsTCFilterActive() {
			t.Fatal("an attached probe should be active")
		}

		if err := ns.nl.LinkDel(dev); err != nil {
			t.Fatal(err)
		}
		if p.IsTCFilterActive() {
			t.Error("a probe whose interface is deleted should be inactive")
		}
		if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("moved interface", func(t *testing.T) {
		m := newTCTestManager(t)
		ns, other := newTestNetns(t), newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)

		if err := ns.nl.LinkSetNsFd(dev, int(other.handle)); err != nil {
			t.Fatal(err)
		}
		moved, err := other.nl.LinkByName("dummy0")
		if err != nil {
			t.Fatal(err)
		}
		// the link follows its interface
		other.requirePrograms(t, moved.Attrs().Index, Ingress, probeID(p))
		if p.IsTCFilterActive() {
			t.Error("a probe whose interface left its namespace should be inactive")
		}

		if err = m.DetachHook(p.ProbeIdentificationPair); err != nil {
			t.Fatal(err)
		}
		other.requirePrograms(t, moved.Attrs().Index, Ingress)
	})

	t.Run("moved and renumbered interface", func(t *testing.T) {
		m := newTCTestManager(t)
		ns, other := newTestNetns(t), newTestNetns(t)
		dev := ns.addLink(t, dummy("dummy0"))
		other.addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "taken", Index: dev.Attrs().Index}})
		p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)

		if err := ns.nl.LinkSetNsFd(dev, int(other.handle)); err != nil {
			t.Fatal(err)
		}
		moved, err := other.nl.LinkByName("dummy0")
		if err != nil {
			t.Fatal(err)
		}
		if moved.Attrs().Index == dev.Attrs().Index {
			t.Fatal("the moved interface should get a new ifindex")
		}
		// an unrelated interface takes the ifindex that the probe was attached to
		ns.addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "reused", Index: dev.Attrs().Index}})
		if p.IsTCFilterActive() {
			t.Error("a probe whose interface left its namespace should be inactive")
		}
	})
}

func TestTCXLinkIfIndex(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns, other := newTestNetns(t), newTestNetns(t)
	dev := ns.addLink(t, dummy("dummy0"))
	other.addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "taken", Index: dev.Attrs().Index}})
	p := ns.cloneTCX(t, m, "probe", dev.Attrs().Index, Ingress, TCXAnchorHead)

	requireIfIndex := func(want int) {
		t.Helper()
		ifindex, err := p.TCXLinkIfIndex()
		if err != nil {
			t.Fatal(err)
		}
		if int(ifindex) != want {
			t.Fatalf("got ifindex %d, want %d", ifindex, want)
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
	if moved.Attrs().Index == dev.Attrs().Index {
		t.Fatal("the moved interface should get a new ifindex")
	}
	requireIfIndex(moved.Attrs().Index)

	if err = other.nl.LinkDel(moved); err != nil {
		t.Fatal(err)
	}
	requireIfIndex(0)

	if err = m.DetachHook(p.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	if _, err = p.TCXLinkIfIndex(); !errors.Is(err, ErrNoTCXLink) {
		t.Errorf("a detached probe returned %v, want %v", err, ErrNoTCXLink)
	}
}

func TestTCXCleansUpDeadLegacyFilters(t *testing.T) {
	requireTCX(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	dev := ns.addLink(t, dummy("dummy0"))
	ifindex := dev.Attrs().Index
	if err := ns.nl.QdiscAdd((&Probe{IfIndex: ifindex}).buildTCClsActQdisc()); err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(tcxTestProgramSpec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	// pids are lower than pid_max
	pidMax, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Fatal(err)
	}
	deadPID := strings.TrimSpace(string(pidMax))
	livePID := strconv.Itoa(os.Getpid())
	filters := map[string]bool{
		"classifier_tcx_test_probe_" + deadPID: false,
		"classifier_tcx_test_probe_" + livePID: true,
		"classifier_tcx_test_other_" + deadPID: true,
	}
	prio := uint16(0)
	for name := range filters {
		prio++
		err = ns.nl.FilterAdd(&netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifindex,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Priority:  prio,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         name,
			DirectAction: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	ns.cloneTCX(t, m, "probe", ifindex, Ingress, TCXAnchorHead)

	list, err := ns.nl.FilterList(dev, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, filter := range list {
		if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
			got = append(got, bpfFilter.Name)
		}
	}
	for name, kept := range filters {
		if slices.Contains(got, name) != kept {
			t.Errorf("filter %s: kept %v, want %v", name, !kept, kept)
		}
	}
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
	if err = unix.Close(handle); err != nil {
		t.Fatal(err)
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

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
}

func TestLegacyTCAttach(t *testing.T) {
	requireRoot(t)
	m := newTCTestManager(t)
	ns := newTestNetns(t)
	dev := ns.addLink(t, dummy("dummy0"))
	p := ns.newProbe("probe", dev.Attrs().Index, Ingress, TCAttachModeLegacy, TCXAnchorTail)
	if err := m.CloneProgram("", p, nil, nil); err != nil {
		t.Fatal(err)
	}

	ids := func() []int {
		filters, err := ns.nl.FilterList(dev, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			t.Fatal(err)
		}
		var ids []int
		for _, filter := range filters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				ids = append(ids, bpfFilter.Id)
			}
		}
		return ids
	}
	if got := ids(); !slices.Equal(got, []int{int(p.ID())}) {
		t.Fatalf("ingress filters: got programs %v, want %d", got, p.ID())
	}
	if !p.IsTCFilterActive() {
		t.Fatal("an attached probe should be active")
	}
	if sock, ok := m.netlinkSocketCache.lookup(ns.id); !ok || sock.tcxNetns != nil {
		t.Error("a legacy attach should open a netlink socket, without copying the namespace handle")
	}

	if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 0 {
		t.Errorf("ingress filters left after DetachHook: %v", got)
	}
}
