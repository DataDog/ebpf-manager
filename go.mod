module github.com/DataDog/ebpf-manager

go 1.21.0

require (
	github.com/cilium/ebpf v0.15.1-0.20240624161703-13a828e0263f
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20230807190133-6afddb37c1f0
	github.com/vishvananda/netns v0.0.4
	golang.org/x/sys v0.22.0
)

require golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
