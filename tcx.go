package manager

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TCAttachMode - (TC classifier) Method used to attach a classifier to its interface
type TCAttachMode uint32

const (
	// TCAttachModeLegacy - Attach the classifier as a filter of a clsact qdisc. This is the default.
	TCAttachModeLegacy TCAttachMode = iota
	// TCAttachModeTCX - Attach the classifier with a TCX link (see HaveTCX). TCX programs run before the filters of
	// clsact qdiscs. TCFilterHandle, TCFilterPrio and TCCleanupQDisc are ignored, TCFilterProtocol must be ETH_P_ALL,
	// and IfIndexNetnsID must be the inode number of the IfIndexNetns network namespace.
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

// HaveTCX - Returns nil if the kernel can attach classifiers with TCX links, or the reason why it can't. It only needs
// the bpf syscall: no network namespace or interface is involved. The result isn't cached.
func HaveTCX() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return fmt.Errorf("couldn't load a classifier to detect TCX support: %w", err)
	}
	defer prog.Close()

	// the kernel only looks the interface up once it has accepted the TCX attach type
	ifindex := ^uint32(0)
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: int(ifindex),
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		_ = l.Close()
		return errors.New("attaching a TCX link to a missing interface succeeded unexpectedly")
	}
	if errors.Is(err, unix.ENODEV) {
		return nil
	}
	return fmt.Errorf("TCX isn't supported: %w", err)
}

func (p *Probe) usesTCX() bool {
	return p.programSpec != nil && p.programSpec.Type == ebpf.SchedCLS && p.TCAttachMode == TCAttachModeTCX
}

// checkTCAttachMode - Validates the attach mode of a TC classifier
func (p *Probe) checkTCAttachMode() error {
	switch p.TCAttachMode {
	case TCAttachModeLegacy:
		return nil
	case TCAttachModeTCX:
	default:
		return fmt.Errorf("unknown TC attach mode %d", p.TCAttachMode)
	}
	if p.TCXAnchor != TCXAnchorTail && p.TCXAnchor != TCXAnchorHead {
		return fmt.Errorf("unknown TCX anchor %d", p.TCXAnchor)
	}
	if p.TCFilterProtocol != 0 && p.TCFilterProtocol != unix.ETH_P_ALL {
		return fmt.Errorf("TCX links can't filter on protocol %#x", p.TCFilterProtocol)
	}
	return nil
}

func (p *Probe) tcxAttachType() ebpf.AttachType {
	if p.NetworkDirection == Egress {
		return ebpf.AttachTCXEgress
	}
	return ebpf.AttachTCXIngress
}

// attachTCX - Attaches the probe to its interface with a TCX link
func (p *Probe) attachTCX() error {
	ntl, nsHandle, err := p.netlinkSocketCache.getTCXNetlinkSocket(p.IfIndexNetns, p.IfIndexNetnsID)
	if err != nil {
		return err
	}
	if nsHandle.IsOpen() {
		defer nsHandle.Close()
	}

	if _, err = p.resolveLink(); err != nil {
		return err
	}

	// lists nothing without clsact qdisc. ENOENT means the filter is gone already, and Attach would take it for success.
	if err = p.cleanupTCFilters(ntl); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("couldn't clean up existing \"clsact\" qdisc filters for %s[%d]: %w", p.IfName, p.IfIndex, err)
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

// TCXLinkIfIndex - (TC classifier) Returns the ifindex reported by the TCX link of the probe. The link follows its
// interface into other network namespaces, where the interface may get another ifindex than IfIndex, and reports 0
// once the interface is unregistered. Returns ErrNotSupported if TCAttachMode isn't TCAttachModeTCX, and ErrNoTCXLink
// if the probe has no TCX link, as when it isn't attached.
func (p *Probe) TCXLinkIfIndex() (uint32, error) {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	if p.TCAttachMode != TCAttachModeTCX {
		return 0, fmt.Errorf("%s isn't attached with TCX: %w", p.ProbeIdentificationPair, ErrNotSupported)
	}
	ifindex, err := p.tcxLinkIfIndex()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", p.ProbeIdentificationPair, err)
	}
	return ifindex, nil
}

// tcxLinkIfIndex - Thread unsafe version of TCXLinkIfIndex
func (p *Probe) tcxLinkIfIndex() (uint32, error) {
	tcxLink, ok := p.progLink.(link.Link)
	if !ok {
		return 0, ErrNoTCXLink
	}
	info, err := tcxLink.Info()
	if err != nil {
		return 0, err
	}
	if info.TCX() == nil {
		return 0, ErrNoTCXLink
	}
	return info.TCX().Ifindex, nil
}

// isTCXLinkActive - A TCX link reports ifindex 0 once its interface is unregistered, but it stays attached to an
// interface that moves to another network namespace: the interface must also still be in the namespace of the probe.
func (p *Probe) isTCXLinkActive() bool {
	// an interface moving into a namespace where its ifindex is taken gets a new one
	if ifindex, err := p.tcxLinkIfIndex(); err != nil || ifindex == 0 || int(ifindex) != p.IfIndex {
		return false
	}
	return p.isInterfaceInNetns()
}

// isInterfaceInNetns - Looks the interface up with the cached netlink socket of the probe's network namespace, and
// never opens a new one: the namespace handle of the probe may be closed already.
func (p *Probe) isInterfaceInNetns() bool {
	ntl, ok := p.netlinkSocketCache.lookup(p.IfIndexNetnsID)
	if !ok {
		return false
	}
	_, err := ntl.Sock.LinkByIndex(p.IfIndex)
	return err == nil
}

// runInNetns - Runs fn in the provided network namespace, or in the current one if ns isn't open. fn runs on a new
// goroutine locked to its thread, so that a thread that can't be moved back to its namespace is terminated when the
// goroutine exits, instead of being reused.
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
