module github.com/DataDog/ebpf-manager

go 1.21.0
toolchain go1.22.5

require (
	github.com/cilium/ebpf v0.17.1
	github.com/vishvananda/netlink v1.3.0
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.29.0
)
