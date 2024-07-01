package manager

type state uint

const (
	reset state = iota
	elfLoaded
	initialized
	stopped
	paused
	running
)
