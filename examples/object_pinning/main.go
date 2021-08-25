package main

import (
	"flag"

	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf-manager/manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kprobe/mkdirat",
				EBPFFuncName: "kprobe_mkdirat",
			},
			PinPath:         "/sys/fs/bpf/mkdirat",
			SyscallFuncName: "mkdirat",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kretprobe/mkdirat",
				EBPFFuncName: "kretprobe_mkdirat",
			},
			SyscallFuncName: "mkdirat",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kprobe/mkdir",
				EBPFFuncName: "kprobe_mkdir",
			},
			PinPath:         "/sys/fs/bpf/mkdir",
			SyscallFuncName: "mkdir",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kretprobe/mkdir",
				EBPFFuncName: "kretprobe_mkdir",
			},
			SyscallFuncName: "mkdir",
		},
	},
	Maps: []*manager.Map{
		{
			Name: "map1",
			MapOptions: manager.MapOptions{
				PinPath: "/sys/fs/bpf/map1",
			},
		},
	},
}

func main() {
	// Parse CLI arguments
	var kill bool
	flag.BoolVar(&kill, "kill", false, "kills the programs suddenly before doing any cleanup")
	flag.Parse()

	logrus.Println("if they exist, pinned object will be automatically loaded")

	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	if kill {
		logrus.Println("=> Stopping the program without cleanup, the pinned map and programs should show up in /sys/fs/bpf/")
		logrus.Println("=> Restart without --kill to load the pinned object from the bpf file system and properly remove them")
		return
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
