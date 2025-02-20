module github.com/DataDog/ebpf-manager

go 1.22.0

require (
	github.com/cilium/ebpf v0.17.2
	github.com/vishvananda/netlink v1.3.0
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sync v0.11.0
	golang.org/x/sys v0.30.0
)

replace github.com/cilium/ebpf => github.com/ti-mo/ebpf v0.5.1-0.20250220092824-fbe9df5b6286
