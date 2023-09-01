package manager

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// attachSocket - Attaches the probe to the provided socket
func (p *Probe) attachSocket() error {
	if err := sockAttach(p.SocketFD, p.program.FD()); err != nil {
		return err
	}
	p.progLink = &socketLink{p.SocketFD, p.program.FD()}
	return nil
}

type socketLink struct {
	sockFD int
	progFD int
}

func (s *socketLink) Close() error {
	return sockDetach(s.sockFD, s.progFD)
}

func (s *socketLink) Pause() error {
	return sockDetach(s.sockFD, s.progFD)
}

func (s *socketLink) Resume() error {
	return sockAttach(s.sockFD, s.progFD)
}

func sockAttach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, progFd)
}

func sockDetach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, progFd)
}
