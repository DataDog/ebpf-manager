module github.com/DataDog/ebpf-manager

go 1.23.0

require (
	github.com/cilium/ebpf v0.18.0
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sync v0.14.0
	golang.org/x/sys v0.33.0
)

replace github.com/cilium/ebpf => github.com/lmb/ebpf v0.7.1-0.20250604084157-ff276d7a4af4
