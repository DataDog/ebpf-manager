package main

import (
	"github.com/DataDog/ebpf-manager/manager"
	"github.com/sirupsen/logrus"
)

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kretprobe/vfs_mkdir",
				EBPFFuncName: "kretprobe_vfs_mkdir",
			},
			HookFuncName: "vfs_mkdir",
		},
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kprobe/vfs_mkdir",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
			HookFuncName: "vfs_mkdir",
		},
	},
}

func main() {
	// Initialize & start m1
	if err := m1.Init(recoverAsset("/prog1.o")); err != nil {
		logrus.Fatal(err)
	}
	if err := m1.Start(); err != nil {
		logrus.Fatal(err)
	}
	logrus.Println("Head over to /sys/kernel/debug/tracing/trace_pipe to see the eBPF programs in action")

	// Start demos
	if err := demoMapEditor(); err != nil {
		logrus.Error(err)
		cleanup()
		return
	}
	if err := demoMapRouter(); err != nil {
		logrus.Error(err)
		cleanup()
		return
	}

	// Close the managers
	if err := m1.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Stop(manager.CleanInternal); err != nil {
		logrus.Fatal(err)
	}
}

func cleanup() {
	_ = m1.Stop(manager.CleanAll)
	_ = m2.Stop(manager.CleanInternal)
}
