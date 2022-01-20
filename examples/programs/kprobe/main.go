package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir",
				EBPFSection:  "kprobe/vfs_mkdir",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "UtimesCommon",
				EBPFSection:  "kretprobe/utimes_common",
				EBPFFuncName: "kretprobe_utimes_common",
			},
			MatchFuncName:   "utimes_common",
			KProbeMaxActive: 100,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID: "", // UID is needed only if there are multiple instances of your program (after using
				// m.CloneProgram for example), or if multiple programs with the exact same section are attaching
				// at the exact same hook point (using m.AddHook for example, or simply because another manager
				// on the system is planning on hooking there).
				EBPFSection:  "kretprobe/mkdirat",
				EBPFFuncName: "kretprobe_mkdirat",
			},
			SyscallFuncName: "mkdirat",
		},
	},
}

func main() {
	options := manager.Options{
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
	}

	// Initialize the manager
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started")
	logrus.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	logrus.Println("=> checkout /sys/kernel/debug/tracing/kprobe_events, utimes_common might have become utimes_common.isra.0")
	logrus.Println("=> Cmd+C to exit")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
