package manager

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	testClassifier = "classifier"
	missingIfIndex = math.MaxInt32
)

// newUnloadedTCManager returns a running manager whose classifier isn't loaded, so that probes can be initialized
// without privileges
func newUnloadedTCManager() *Manager {
	return &Manager{
		collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
			testClassifier: {Name: testClassifier, Type: ebpf.SchedCLS, SectionName: "classifier/" + testClassifier},
		}},
		collection:         &ebpf.Collection{Programs: map[string]*ebpf.Program{testClassifier: nil}},
		netlinkSocketCache: newNetlinkSocketCache(),
		state:              running,
	}
}

// newFakeTCProbe returns a probe in the requested state, holding a zero program: it can be unpinned, but not closed,
// which Stop only does after an attach attempt.
func newFakeTCProbe(m *Manager, uid string, mode TCAttachMode, s state) *Probe {
	return &Probe{
		ProbeIdentificationPair: ProbeIdentificationPair{UID: uid, EBPFFuncName: testClassifier},
		netlinkSocketCache:      m.netlinkSocketCache,
		program:                 &ebpf.Program{},
		programSpec:             &ebpf.ProgramSpec{Type: ebpf.SchedCLS, SectionName: "classifier/" + testClassifier},
		state:                   s,
		Enabled:                 true,
		NetworkDirection:        Ingress,
		TCAttachMode:            mode,
	}
}

// openCurrentNetns returns a handle on the network namespace of the test, and its ID
func openCurrentNetns(t *testing.T) (*os.File, uint32) {
	t.Helper()
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	var stat unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	return f, uint32(stat.Ino)
}

// cacheCurrentNetns caches a netlink socket of the current network namespace as the socket of nsID: opening one from a
// namespace handle needs privileges.
func cacheCurrentNetns(t *testing.T, m *Manager, nsID uint32) *NetlinkSocket {
	t.Helper()
	sock, err := NewNetlinkSocket(0)
	if err != nil {
		t.Fatal(err)
	}
	m.netlinkSocketCache.cache[nsID] = sock
	t.Cleanup(m.netlinkSocketCache.cleanup)
	return sock
}

// lookup returns the cached netlink socket of nsID, without opening a new one
func (nsc *netlinkSocketCache) lookup(nsID uint32) (*NetlinkSocket, bool) {
	nsc.Lock()
	defer nsc.Unlock()
	sock, ok := nsc.cache[nsID]
	return sock, ok
}

type closeCounter struct {
	closed int
}

func (c *closeCounter) Close() error {
	c.closed++
	return nil
}

// fakeLink can't report an ifindex: only cilium/ebpf can build a link info with TCX details
type fakeLink struct {
	link.Link
	info *link.Info
	err  error
}

func (l *fakeLink) Info() (*link.Info, error) {
	return l.info, l.err
}

func TestTCAttachModeDefaults(t *testing.T) {
	var p Probe
	if p.TCAttachMode != TCAttachModeLegacy || p.TCXAnchor != TCXAnchorTail {
		t.Errorf("zero probe: got mode %s and anchor %d, want legacy and tail", p.TCAttachMode, p.TCXAnchor)
	}

	c := (&Probe{TCAttachMode: TCAttachModeTCX, TCXAnchor: TCXAnchorHead}).Copy()
	if c.TCAttachMode != TCAttachModeTCX || c.TCXAnchor != TCXAnchorHead {
		t.Errorf("copy: got mode %s and anchor %d, want tcx and head", c.TCAttachMode, c.TCXAnchor)
	}
}

func TestTCAttachModeInit(t *testing.T) {
	tests := []struct {
		name     string
		mode     TCAttachMode
		anchor   TCXAnchor
		protocol uint16
		wantErr  bool
	}{
		{name: "legacy"},
		{name: "legacy ignores the anchor", anchor: 42},
		{name: "tcx at the tail", mode: TCAttachModeTCX},
		{name: "tcx at the head", mode: TCAttachModeTCX, anchor: TCXAnchorHead},
		{name: "tcx with every protocol", mode: TCAttachModeTCX, protocol: unix.ETH_P_ALL},
		{name: "tcx with one protocol", mode: TCAttachModeTCX, protocol: unix.ETH_P_ARP, wantErr: true},
		{name: "unknown mode", mode: 42, wantErr: true},
		{name: "unknown anchor", mode: TCAttachModeTCX, anchor: 42, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Probe{
				ProbeIdentificationPair: ProbeIdentificationPair{UID: "test", EBPFFuncName: testClassifier},
				Enabled:                 true,
				NetworkDirection:        Ingress,
				TCFilterProtocol:        tt.protocol,
				TCAttachMode:            tt.mode,
				TCXAnchor:               tt.anchor,
			}
			if err := p.init(newUnloadedTCManager()); (err != nil) != tt.wantErr {
				t.Errorf("init returned %v, want an error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCXAttachMissingInterface(t *testing.T) {
	p := newFakeTCProbe(newUnloadedTCManager(), "test", TCAttachModeTCX, initialized)
	p.IfIndex = missingIfIndex

	var notFound netlink.LinkNotFoundError
	if err := p.attach(); !errors.As(err, &notFound) {
		t.Fatalf("attach returned %v, want a netlink.LinkNotFoundError", err)
	}
}

func TestTCXNetnsHandleCopy(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	m := newUnloadedTCManager()
	sock := cacheCurrentNetns(t, m, nsID)

	attach := func(mode TCAttachMode, nsHandle uintptr) {
		t.Helper()
		p := newFakeTCProbe(m, "test", mode, initialized)
		p.IfIndex = missingIfIndex
		p.IfIndexNetns = uint64(nsHandle)
		p.IfIndexNetnsID = nsID

		var notFound netlink.LinkNotFoundError
		if err := p.attach(); !errors.As(err, &notFound) {
			t.Fatalf("%s attach returned %v, want a netlink.LinkNotFoundError", mode, err)
		}
	}

	attach(TCAttachModeLegacy, nsFile.Fd())
	if sock.tcxNetns != nil {
		t.Fatal("a legacy attach shouldn't copy the namespace handle")
	}

	attach(TCAttachModeTCX, nsFile.Fd())
	nsCopy := sock.tcxNetns
	if nsCopy == nil {
		t.Fatal("the first TCX attach in a namespace should copy its handle")
	}
	if err := checkNetnsHandle(uint64(nsCopy.Fd()), nsID); err != nil {
		t.Fatal(err)
	}

	// callers close their handle once attached, so its number can point to any file afterwards
	if err := nsFile.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	attach(TCAttachModeTCX, other.Fd())
	if sock.tcxNetns != nsCopy {
		t.Fatal("later TCX attaches should reuse the copy of the first handle")
	}

	if err = m.CleanupNetworkNamespace(nsID); err != nil {
		t.Fatal(err)
	}
	if _, err = nsCopy.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("CleanupNetworkNamespace should close the handle copy, stat returned %v", err)
	}
}

func TestTCXNetnsHandleCopyClosedOnStop(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	m := newUnloadedTCManager()
	sock := cacheCurrentNetns(t, m, nsID)

	_, handle, err := m.netlinkSocketCache.getTCXNetlinkSocket(uint64(nsFile.Fd()), nsID)
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()
	nsCopy := sock.tcxNetns

	m.netlinkSocketCache.cleanup()
	if _, err = nsCopy.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("stopping the manager should close the handle copy, stat returned %v", err)
	}
}

func TestTCXNetnsHandleCheck(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	tests := []struct {
		name     string
		nsHandle uint64
		nsID     uint32
	}{
		{name: "another file", nsHandle: uint64(devNull.Fd()), nsID: nsID},
		{name: "another namespace", nsHandle: uint64(nsFile.Fd()), nsID: nsID + 1},
		{name: "closed handle", nsHandle: math.MaxInt32, nsID: nsID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newUnloadedTCManager()
			if _, _, err := m.netlinkSocketCache.getTCXNetlinkSocket(tt.nsHandle, tt.nsID); !errors.Is(err, ErrNetnsSwitch) {
				t.Fatalf("got %v, want %v", err, ErrNetnsSwitch)
			}
			if _, ok := m.netlinkSocketCache.lookup(tt.nsID); ok {
				t.Error("no netlink socket should be opened with a mismatched handle")
			}
		})
	}
}

func TestTCXIsTCFilterActiveWithoutLink(t *testing.T) {
	p := newFakeTCProbe(newUnloadedTCManager(), "test", TCAttachModeTCX, running)
	if p.IsTCFilterActive() {
		t.Error("a TCX probe without link can't be active")
	}
}

func TestTCXLinkIfIndexWithoutTCXLink(t *testing.T) {
	legacy := newFakeTCProbe(newUnloadedTCManager(), "legacy", TCAttachModeLegacy, running)
	if _, err := legacy.TCXLinkIfIndex(); !errors.Is(err, ErrNotSupported) {
		t.Errorf("a legacy probe returned %v, want %v", err, ErrNotSupported)
	}

	infoErr := errors.New("link info error")
	tests := []struct {
		name     string
		progLink io.Closer
		wantErr  error
	}{
		{name: "no link", wantErr: ErrNoTCXLink},
		{name: "not a TCX link", progLink: &fakeLink{info: &link.Info{Type: link.XDPType}}, wantErr: ErrNoTCXLink},
		{name: "link info error", progLink: &fakeLink{err: infoErr}, wantErr: infoErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newFakeTCProbe(newUnloadedTCManager(), "test", TCAttachModeTCX, running)
			p.progLink = tt.progLink
			if ifindex, err := p.TCXLinkIfIndex(); !errors.Is(err, tt.wantErr) || ifindex != 0 {
				t.Errorf("got ifindex %d and error %v, want %v", ifindex, err, tt.wantErr)
			}
			if p.IsTCFilterActive() {
				t.Error("a probe without TCX link can't be active")
			}
		})
	}
}

func TestTCXNetnsHandleForActiveCheck(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	m := newUnloadedTCManager()
	cacheCurrentNetns(t, m, nsID)

	if handle, err := m.netlinkSocketCache.tcxNetnsHandle(0); err != nil || handle.IsOpen() {
		t.Errorf("a probe without namespace handle should be checked from the current namespace, got %v", err)
	}

	// no TCX attach copied the handle of nsID, and nsID+1 isn't cached
	for _, id := range []uint32{nsID, nsID + 1} {
		if _, err := m.netlinkSocketCache.tcxNetnsHandle(id); !errors.Is(err, ErrNetnsSwitch) {
			t.Errorf("namespace %d: got %v, want %v", id, err, ErrNetnsSwitch)
		}
	}
	if _, ok := m.netlinkSocketCache.lookup(nsID + 1); ok {
		t.Error("checking a probe shouldn't open a netlink socket")
	}

	_, attachHandle, err := m.netlinkSocketCache.getTCXNetlinkSocket(uint64(nsFile.Fd()), nsID)
	if err != nil {
		t.Fatal(err)
	}
	_ = attachHandle.Close()
	handle, err := m.netlinkSocketCache.tcxNetnsHandle(nsID)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err = checkNetnsHandle(uint64(handle), nsID); err != nil {
		t.Error(err)
	}
}

func TestTCXAttachErrorsAreReported(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	// setns rejects a handle that isn't a namespace with EINVAL
	switchErr := runInNetns(netns.NsHandle(devNull.Fd()), func() error { return nil })
	if !errors.Is(switchErr, ErrNetnsSwitch) || !errors.Is(switchErr, unix.EINVAL) {
		t.Fatalf("got %v, want %v wrapping %v", switchErr, ErrNetnsSwitch, unix.EINVAL)
	}

	tests := []struct {
		name        string
		err         error
		unavailable bool
	}{
		{name: "missing hook point", err: unix.ENOENT, unavailable: true},
		{name: "unsupported hook point", err: unix.EINVAL, unavailable: true},
		{name: "missing interface", err: unix.ENODEV},
		{name: "namespace switch", err: switchErr},
		{name: "tcx attach", err: fmt.Errorf("%w to %s[%d]: %w", ErrTCXAttach, "dummy0", 2, unix.EINVAL)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("couldn't start probe: %w", tt.err)
			if got := isHookUnavailable(err); got != tt.unavailable {
				t.Errorf("isHookUnavailable(%v) returned %v, want %v", err, got, tt.unavailable)
			}
		})
	}
}

func TestTCXPause(t *testing.T) {
	m := newUnloadedTCManager()

	tcx := newFakeTCProbe(m, "tcx", TCAttachModeTCX, running)
	tcx.bypassIndex = 1
	tcx.bypassMap = &Map{}
	if err := tcx.Pause(); !errors.Is(err, ErrNotSupported) {
		t.Errorf("pausing a TCX probe returned %v, want %v", err, ErrNotSupported)
	}
	if !tcx.IsRunning() || tcx.state == paused {
		t.Error("a TCX probe should keep running when it can't be paused")
	}

	legacy := newFakeTCProbe(m, "legacy", TCAttachModeLegacy, running)
	if err := legacy.Pause(); err != nil {
		t.Errorf("pausing a legacy probe without bypass returned %v", err)
	}
}

func TestTCXDetachHookClosesLink(t *testing.T) {
	m := newUnloadedTCManager()
	first := newFakeTCProbe(m, "first", TCAttachModeTCX, running)
	second := newFakeTCProbe(m, "second", TCAttachModeTCX, running)
	firstLink, secondLink := &closeCounter{}, &closeCounter{}
	first.progLink, second.progLink = firstLink, secondLink
	m.Probes = []*Probe{first, second}

	// DetachHook stops a probe while another clone of its program is left, and only detaches the last one
	for _, p := range []*Probe{first, second} {
		if err := m.DetachHook(p.ProbeIdentificationPair); err != nil {
			t.Fatal(err)
		}
	}
	if firstLink.closed != 1 || secondLink.closed != 1 {
		t.Errorf("links closed %d and %d times, want once each", firstLink.closed, secondLink.closed)
	}
	if first.progLink != nil || second.progLink != nil {
		t.Error("detached probes shouldn't keep their link")
	}
	if len(m.Probes) != 0 {
		t.Errorf("%d probes left after DetachHook", len(m.Probes))
	}
}

func TestHaveTCXWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged user")
	}
	if err := HaveTCX(); err == nil {
		t.Error("loading a classifier needs privileges, so HaveTCX should report TCX as unavailable")
	}
}
