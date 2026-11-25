package manager

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TCAttachMode - (TC classifier) Method used to attach a classifier to its interface
type TCAttachMode uint32

const (
	// TCAttachModeLegacy - Attach the classifier as a filter of a clsact qdisc. This is the default.
	TCAttachModeLegacy TCAttachMode = iota
	// TCAttachModeTCX - Attach the classifier with a TCX link (Linux 6.6+), which runs before the filters of clsact
	// qdiscs. TCFilterHandle, TCFilterPrio and TCCleanupQDisc are ignored, TCFilterProtocol must be ETH_P_ALL, and
	// IfIndexNetnsID must be the inode number of the IfIndexNetns network namespace. The filters that previous managers
	// left on the interface aren't removed.
	TCAttachModeTCX
)

func (m TCAttachMode) String() string {
	switch m {
	case TCAttachModeLegacy:
		return "legacy"
	case TCAttachModeTCX:
		return "tcx"
	default:
		return fmt.Sprintf("TCAttachMode(%d)", m)
	}
}

// TCXAnchor - (TC classifier) Position of a TCX link among the programs attached to the same hook
type TCXAnchor uint32

const (
	// TCXAnchorTail - Insert the link after all the programs of the hook. This is the default.
	TCXAnchorTail TCXAnchor = iota
	// TCXAnchorHead - Insert the link before all the programs of the hook: links anchored at the head run in the
	// reverse order of their attachment.
	TCXAnchorHead
)

func (a TCXAnchor) anchor() link.Anchor {
	if a == TCXAnchorHead {
		return link.Head()
	}
	return link.Tail()
}

func (p *Probe) tcxAttachType() ebpf.AttachType {
	if p.NetworkDirection == Egress {
		return ebpf.AttachTCXEgress
	}
	return ebpf.AttachTCXIngress
}

// attachTCX - Attaches the probe to its interface with a TCX link
func (p *Probe) attachTCX() error {
	nsHandle, err := p.netlinkSocketCache.tcxNetnsHandle(p.IfIndexNetns, p.IfIndexNetnsID)
	if err != nil {
		return err
	}
	if nsHandle.IsOpen() {
		defer nsHandle.Close()
	}
	if _, err = p.resolveLink(); err != nil {
		return err
	}

	var tcxLink link.Link
	err = runInNetns(nsHandle, func() error {
		var attachErr error
		tcxLink, attachErr = link.AttachTCX(link.TCXOptions{
			Interface: p.IfIndex,
			Program:   p.program,
			Attach:    p.tcxAttachType(),
			Anchor:    p.TCXAnchor.anchor(),
		})
		if attachErr != nil {
			return fmt.Errorf("%w to %s[%d]: %w", ErrTCXAttach, p.IfName, p.IfIndex, attachErr)
		}
		return nil
	})
	if tcxLink != nil {
		p.progLink = tcxLink
	}
	return err
}

// detachTCX - Closes the TCX link of the probe, which detaches it whatever the network namespace of its interface
func (p *Probe) detachTCX() error {
	if p.progLink == nil {
		return nil
	}
	if err := p.progLink.Close(); err != nil {
		return fmt.Errorf("couldn't close the TCX link of %s: %w", p.ProbeIdentificationPair, err)
	}
	p.progLink = nil
	return nil
}

// TCXLinkIfIndex - (TC classifier) Returns the ifindex reported by the TCX link of the probe: the link follows its
// interface into other network namespaces, and reports 0 once the interface is unregistered. Returns ErrNotSupported
// if TCAttachMode isn't TCAttachModeTCX, and ErrNoTCXLink if the probe isn't attached.
func (p *Probe) TCXLinkIfIndex() (uint32, error) {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	if p.TCAttachMode != TCAttachModeTCX {
		return 0, fmt.Errorf("%s isn't attached with TCX: %w", p.ProbeIdentificationPair, ErrNotSupported)
	}
	info, err := p.tcxLinkInfo()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", p.ProbeIdentificationPair, err)
	}
	return info.TCX().Ifindex, nil
}

// tcxLinkInfo - Thread unsafe: returns the info of the TCX link of the probe
func (p *Probe) tcxLinkInfo() (*link.Info, error) {
	tcxLink, ok := p.progLink.(link.Link)
	if !ok {
		return nil, ErrNoTCXLink
	}
	info, err := tcxLink.Info()
	if err != nil {
		return nil, err
	}
	if info.TCX() == nil {
		return nil, ErrNoTCXLink
	}
	return info, nil
}

// isTCXLinkActive - A TCX link follows its interface into other network namespaces, and another interface can then take
// its ifindex in the namespace of the probe: the link must be on the hook of IfIndex in that namespace.
func (p *Probe) isTCXLinkActive() bool {
	info, err := p.tcxLinkInfo()
	if err != nil || int(info.TCX().Ifindex) != p.IfIndex {
		return false
	}
	nsHandle, err := p.netlinkSocketCache.tcxNetnsHandle(p.IfIndexNetns, p.IfIndexNetnsID)
	if err != nil {
		return false
	}
	if nsHandle.IsOpen() {
		defer nsHandle.Close()
	}

	var res *link.QueryResult
	err = runInNetns(nsHandle, func() (err error) {
		// the hook can grow between the two syscalls of a query
		for range 3 {
			if res, err = link.QueryPrograms(link.QueryOptions{Target: p.IfIndex, Attach: p.tcxAttachType()}); !errors.Is(err, unix.ENOSPC) {
				break
			}
		}
		return err
	})
	if err != nil {
		return false
	}
	for _, prog := range res.Programs {
		if id, ok := prog.LinkID(); ok && id == info.ID {
			return true
		}
	}
	return false
}

// runInNetns - Runs fn in the provided network namespace, or in the current one if ns isn't open, on a goroutine locked
// to its thread: a thread that can't go back to its namespace is terminated with the goroutine instead of being reused.
func runInNetns(ns netns.NsHandle, fn func() error) error {
	if !ns.IsOpen() {
		return fn()
	}

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origin, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("%w: couldn't get the current namespace: %w", ErrNetnsSwitch, err)
			return
		}
		defer origin.Close()

		if err = netns.Set(ns); err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("%w: couldn't enter the namespace: %w", ErrNetnsSwitch, err)
			return
		}
		fnErr := fn()
		if err = netns.Set(origin); err != nil {
			errCh <- errors.Join(fnErr, fmt.Errorf("%w: couldn't restore the original namespace: %w", ErrNetnsSwitch, err))
			return
		}
		runtime.UnlockOSThread()
		errCh <- fnErr
	}()
	return <-errCh
}
