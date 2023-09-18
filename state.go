package manager

type state uint

const (
	reset state = iota
	initialized
	stopped
	paused
	running
)
