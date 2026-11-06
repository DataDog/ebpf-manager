package manager

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// NetlinkSocket - (TC classifier programs and XDP) Netlink socket cache entry holding the netlink socket and the
// TC filter count
type NetlinkSocket struct {
	Sock          *netlink.Handle
	filterMutex   sync.Mutex
	tcFilterCount map[int]int

	// tcxNetns - Copy of the network namespace handle used by TCX attaches, owned by the entry
	tcxNetns *os.File
}

func (ns *NetlinkSocket) closeNetns() {
	if ns.tcxNetns != nil {
		_ = ns.tcxNetns.Close()
		ns.tcxNetns = nil
	}
}

// NewNetlinkSocket - Returns a new NetlinkSocket instance
func NewNetlinkSocket(nsHandle uint64) (*NetlinkSocket, error) {
	var err error
	var netnsHandle netns.NsHandle
	cacheEntry := NetlinkSocket{
		tcFilterCount: make(map[int]int),
	}

	if nsHandle == 0 {
		netnsHandle = netns.None()
	} else {
		netnsHandle = netns.NsHandle(nsHandle)
	}

	// Open a netlink socket for the requested namespace
	cacheEntry.Sock, err = netlink.NewHandleAt(netnsHandle, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("couldn't open a netlink socket: %w", err)
	}
	return &cacheEntry, nil
}

// IncreaseFilterCount increases the count for the given index in a thread-safe manner. The return value is the new count.
func (ns *NetlinkSocket) IncreaseFilterCount(index int) {
	ns.filterMutex.Lock()
	defer ns.filterMutex.Unlock()
	ns.tcFilterCount[index]++
}

// DecreaseFilterCount decreases the count for the given index in a thread-safe manner. It will delete the entry if the count reaches 0.
// The return value is the count after the decrease. If the entry was deleted, the return value is 0.
func (ns *NetlinkSocket) DecreaseFilterCount(index int) int {
	ns.filterMutex.Lock()
	defer ns.filterMutex.Unlock()
	ns.tcFilterCount[index]--

	if ns.tcFilterCount[index] <= 0 {
		delete(ns.tcFilterCount, index)
		return 0
	}

	return ns.tcFilterCount[index]
}

type netlinkSocketCache struct {
	sync.Mutex
	cache map[uint32]*NetlinkSocket
}

func newNetlinkSocketCache() *netlinkSocketCache {
	return &netlinkSocketCache{
		cache: make(map[uint32]*NetlinkSocket),
	}
}

// getNetlinkSocket - Returns a netlink socket in the requested network namespace from cache or creates a new one.
// TC classifiers are attached by creating a qdisc on the requested interface. A netlink socket
// is required to create a qdisc (or to attach an XDP program to an interface). Since this socket can be re-used for
// multiple probes, instantiate the connection at the manager level and cache the netlink socket. The provided nsID
// should be the ID of the network namespaced returned by a readlink on `/proc/[pid]/ns/net` for a [pid] that lives in
// the network namespace pointed to by the nsHandle.
func (nsc *netlinkSocketCache) getNetlinkSocket(nsHandle uint64, nsID uint32) (*NetlinkSocket, error) {
	nsc.Lock()
	defer nsc.Unlock()

	sock, ok := nsc.cache[nsID]
	if ok {
		return sock, nil
	}

	cacheEntry, err := NewNetlinkSocket(nsHandle)
	if err != nil {
		return nil, fmt.Errorf("namespace %v: %w", nsID, err)
	}

	nsc.cache[nsID] = cacheEntry
	return cacheEntry, nil
}

// getTCXNetlinkSocket - Returns the netlink socket of the requested network namespace, and a new handle on that
// namespace that the caller must close (netns.None() for the current namespace, when nsHandle is 0). The entry keeps a
// copy of the first nsHandle it gets and ignores the next ones, since callers close their handle once attached.
func (nsc *netlinkSocketCache) getTCXNetlinkSocket(nsHandle uint64, nsID uint32) (*NetlinkSocket, netns.NsHandle, error) {
	nsc.Lock()
	defer nsc.Unlock()

	sock, ok := nsc.cache[nsID]
	if !ok || sock.tcxNetns == nil {
		if nsHandle != 0 {
			if err := checkNetnsHandle(nsHandle, nsID); err != nil {
				return nil, netns.None(), err
			}
		}
		if !ok {
			var err error
			if sock, err = NewNetlinkSocket(nsHandle); err != nil {
				return nil, netns.None(), fmt.Errorf("namespace %v: %w", nsID, err)
			}
			nsc.cache[nsID] = sock
		}
		if nsHandle == 0 {
			return sock, netns.None(), nil
		}
		fd, err := unix.FcntlInt(uintptr(nsHandle), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, netns.None(), fmt.Errorf("%w: couldn't copy the handle of namespace %d: %w", ErrNetnsSwitch, nsID, err)
		}
		sock.tcxNetns = os.NewFile(uintptr(fd), fmt.Sprintf("net:[%d]", nsID))
	}

	fd, err := unix.FcntlInt(sock.tcxNetns.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, netns.None(), fmt.Errorf("%w: couldn't copy the handle of namespace %d: %w", ErrNetnsSwitch, nsID, err)
	}
	return sock, netns.NsHandle(fd), nil
}

// checkNetnsHandle - Makes sure that nsHandle refers to the network namespace nsID: a closed handle number can be
// reused by any other file.
func checkNetnsHandle(nsHandle uint64, nsID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(nsHandle), &stat); err != nil {
		return fmt.Errorf("%w: invalid handle %d for namespace %d: %w", ErrNetnsSwitch, nsHandle, nsID, err)
	}
	if stat.Ino != uint64(nsID) {
		return fmt.Errorf("%w: handle %d refers to inode %d instead of namespace %d", ErrNetnsSwitch, nsHandle, stat.Ino, nsID)
	}
	return nil
}

// lookup - Returns the cached netlink socket of the requested network namespace, without opening a new one
func (nsc *netlinkSocketCache) lookup(nsID uint32) (*NetlinkSocket, bool) {
	if nsc == nil {
		return nil, false
	}
	nsc.Lock()
	defer nsc.Unlock()

	sock, ok := nsc.cache[nsID]
	return sock, ok
}

// cleanup - Cleans up all opened netlink sockets in cache. This function is expected to be called when a
// manager is stopped.
func (nsc *netlinkSocketCache) cleanup() {
	nsc.Lock()
	defer nsc.Unlock()

	for key, s := range nsc.cache {
		delete(nsc.cache, key)
		// close the netlink socket
		s.Sock.Close()
		s.closeNetns()
	}
}

func (nsc *netlinkSocketCache) remove(nsID uint32) {
	nsc.Lock()
	defer nsc.Unlock()

	s, ok := nsc.cache[nsID]
	if ok {
		delete(nsc.cache, nsID)

		// close the netlink socket
		s.Sock.Close()
		s.closeNetns()
	}
}

func (m *Manager) GetNetlinkSocket(nsHandle uint64, nsID uint32) (*NetlinkSocket, error) {
	return m.netlinkSocketCache.getNetlinkSocket(nsHandle, nsID)
}

// CleanupNetworkNamespace - Cleans up all references to the provided network namespace within the manager. This means
// that any TC classifier or XDP probe in that network namespace will be stopped and all opened netlink socket in that
// namespace will be closed.
// WARNING: Don't forget to call this method if you've provided a IfIndexNetns and IfIndexNetnsID to one of the probes
// of this manager. Failing to call this cleanup function may lead to leaking the network namespace. Only call this
// function when you're sure that the manager no longer needs to perform anything in the provided network namespace (or
// else call NewNetlinkSocket first).
func (m *Manager) CleanupNetworkNamespace(nsID uint32) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}

	var errs []error
	var toDelete []int
	for i, probe := range m.Probes {
		if probe.IfIndexNetnsID != nsID {
			continue
		}

		// stop the probe
		errs = append(errs, probe.Stop())

		// disable probe
		probe.Enabled = false

		// append probe to delete (biggest indexes first)
		toDelete = append([]int{i}, toDelete...)
	}

	// delete all netlink sockets, along with netns handles
	m.netlinkSocketCache.remove(nsID)

	// delete probes
	for _, i := range toDelete {
		// we delete the biggest indexes first, so we should be good to go !
		m.Probes = append(m.Probes[:i], m.Probes[i+1:]...)
	}
	return errors.Join(errs...)
}

// ResolveLink - Resolves the Probe's network interface
func (p *Probe) ResolveLink() (netlink.Link, error) {
	return p.resolveLink()
}

func (p *Probe) resolveLink() (netlink.Link, error) {
	if p.link != nil {
		return p.link, nil
	}

	// get a netlink socket in the probe network namespace
	ntl, err := p.getNetlinkSocket()
	if err != nil {
		return nil, err
	}

	if p.IfIndex > 0 {
		p.link, err = ntl.Sock.LinkByIndex(p.IfIndex)
		if err != nil {
			return nil, fmt.Errorf("couldn't resolve interface with IfIndex %d in namespace %d: %w", p.IfIndex, p.IfIndexNetnsID, err)
		}
	} else if len(p.IfName) > 0 {
		p.link, err = ntl.Sock.LinkByName(p.IfName)
		if err != nil {
			return nil, fmt.Errorf("couldn't resolve interface with IfName %s in namespace %d: %w", p.IfName, p.IfIndexNetnsID, err)
		}
	} else {
		return nil, ErrInterfaceNotSet
	}

	attrs := p.link.Attrs()
	if attrs != nil {
		p.IfIndex = attrs.Index
		p.IfName = attrs.Name
	}

	return p.link, nil
}
