module github.com/DataDog/ebpf-manager

go 1.21.0

require (
	github.com/cilium/ebpf v0.16.0
	github.com/vishvananda/netlink v1.3.0
	github.com/vishvananda/netns v0.0.4
	golang.org/x/sys v0.26.0
)

require golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect

replace github.com/cilium/ebpf => github.com/brycekahle/ebpf v0.0.0-20241213212444-57536358ae02
