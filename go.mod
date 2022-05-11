module github.com/DataDog/ebpf-manager

go 1.15

require (
	github.com/DataDog/gopsutil v0.0.0-20200624212600-1b53412ef321
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/cilium/ebpf v0.8.2-0.20220511142539-2e33f5e2fb54
	github.com/hashicorp/go-multierror v1.1.1
	github.com/sirupsen/logrus v1.8.1
	github.com/vishvananda/netlink v1.1.1-0.20220316193741-b112db377d18
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	golang.org/x/sys v0.0.0-20220503163025-988cb79eb6c6
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
