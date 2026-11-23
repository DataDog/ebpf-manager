package manager

import (
	"errors"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
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

// lookup returns the cached netlink socket of nsID, without opening a new one
func (nsc *netlinkSocketCache) lookup(nsID uint32) (*NetlinkSocket, bool) {
	nsc.Lock()
	defer nsc.Unlock()
	sock, ok := nsc.cache[nsID]
	return sock, ok
}

func TestTCXFilterProtocol(t *testing.T) {
	for _, tt := range []struct {
		mode     TCAttachMode
		protocol uint16
		wantErr  bool
	}{
		{mode: TCAttachModeLegacy, protocol: unix.ETH_P_ARP},
		{mode: TCAttachModeTCX, protocol: unix.ETH_P_ALL},
		{mode: TCAttachModeTCX, protocol: unix.ETH_P_ARP, wantErr: true},
	} {
		p := &Probe{
			ProbeIdentificationPair: ProbeIdentificationPair{UID: "test", EBPFFuncName: testClassifier},
			Enabled:                 true,
			NetworkDirection:        Ingress,
			TCFilterProtocol:        tt.protocol,
			TCAttachMode:            tt.mode,
		}
		if err := p.init(newUnloadedTCManager()); (err != nil) != tt.wantErr {
			t.Errorf("%s probe with protocol %#x: init returned %v", tt.mode, tt.protocol, err)
		}
	}
}

func TestTCXNetnsHandleCopy(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	m := newUnloadedTCManager()
	// opening a netlink socket from a namespace handle needs privileges
	sock, err := NewNetlinkSocket(0)
	if err != nil {
		t.Fatal(err)
	}
	m.netlinkSocketCache.cache[nsID] = sock
	t.Cleanup(m.netlinkSocketCache.cleanup)

	// attach fails once the handle is copied, on the missing interface. Unlike Attach, it doesn't close the program,
	// which would panic on a zero program.
	attach := func(mode TCAttachMode, nsHandle uintptr) {
		t.Helper()
		p := &Probe{
			ProbeIdentificationPair: ProbeIdentificationPair{UID: "test", EBPFFuncName: testClassifier},
			netlinkSocketCache:      m.netlinkSocketCache,
			program:                 &ebpf.Program{},
			programSpec:             &ebpf.ProgramSpec{Type: ebpf.SchedCLS},
			state:                   initialized,
			Enabled:                 true,
			NetworkDirection:        Ingress,
			TCAttachMode:            mode,
			IfIndex:                 missingIfIndex,
			IfIndexNetns:            uint64(nsHandle),
			IfIndexNetnsID:          nsID,
		}
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

	// callers close their handle once attached, so its number can point to any file afterwards
	if err = nsFile.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
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

func TestTCXNetnsHandleCheck(t *testing.T) {
	nsFile, nsID := openCurrentNetns(t)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	for name, tt := range map[string]struct {
		nsHandle uint64
		nsID     uint32
	}{
		"another file":      {uint64(devNull.Fd()), nsID},
		"another namespace": {uint64(nsFile.Fd()), nsID + 1},
		"closed handle":     {math.MaxInt32, nsID},
	} {
		m := newUnloadedTCManager()
		if _, err := m.netlinkSocketCache.tcxNetnsHandle(tt.nsHandle, tt.nsID); !errors.Is(err, ErrNetnsSwitch) {
			t.Errorf("%s: got %v, want %v", name, err, ErrNetnsSwitch)
		}
		if _, ok := m.netlinkSocketCache.lookup(tt.nsID); ok {
			t.Errorf("%s: no netlink socket should be opened with a mismatched handle", name)
		}
	}
}
