package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe.o
var Probe []byte

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir1",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_utimes_common",
			},
			MatchFuncName: "utimes",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_vfs_opennnnnn",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_exclude",
			},
		},
	},
}

var options1 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir1",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						UID:          "MyVFSMkdir1",
						EBPFFuncName: "kprobe_vfs_mkdir",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_utimes_common",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_utimes_common",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_vfs_opennnnnn",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_exclude",
					},
				},
			},
		},
		&manager.BestEffort{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_vfs_opennnnnn",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_exclude",
					},
				},
			},
		}},
	ExcludedFunctions: []string{
		"kprobe_exclude2",
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir2",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_utimes_common",
			},
			MatchFuncName: "utimes_common",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_vfs_opennnnnn",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_exclude",
			},
		},
	},
}

var options2 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir2",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_vfs_opennnnnn",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_vfs_opennnnnn",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "kprobe_exclude",
					},
				},
			},
		},
	},
	ExcludedFunctions: []string{
		"kprobe_exclude",
	},
}

var m3 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir2",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_utimes_common",
			},
			MatchFuncName: "utimes_common",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_vfs_opennnnnn",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_exclude",
			},
		},
	},
}

func main() {
	// Initialize the managers
	if err := m1.InitWithOptions(bytes.NewReader(Probe), options1); err != nil {
		logrus.Fatal(err)
	}

	oldID := manager.ProbeIdentificationPair{
		EBPFFuncName: "kprobe_exclude",
		UID:          "",
	}
	newID := manager.ProbeIdentificationPair{
		EBPFFuncName: "kprobe_exclude",
		UID:          "new",
	}
	if err := m1.RenameProbeIdentificationPair(oldID, newID); err != nil {
		logrus.Fatal(err)
	}

	_, ok := m1.GetProbe(newID)
	if !ok {
		logrus.Fatal("RenameProbeIdentificationPair failed")
	}

	// Start m1
	if err := m1.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("m1 successfully started")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	if err := m1.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m2 (an error is expected)")
	// Initialize the managers
	if err := m2.InitWithOptions(bytes.NewReader(Probe), options2); err != nil {
		logrus.Fatal(err)
	}

	// Start m2
	if err := m2.Start(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m3 (an error is expected)")
	if err := m3.Init(bytes.NewReader(Probe)); err != nil {
		logrus.Fatal(err)
	}

	// Start m3
	if err := m3.Start(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("updating activated probes of m3 (no error is expected)")
	if err := m3.Init(bytes.NewReader(Probe)); err != nil {
		logrus.Fatal(err)
	}

	mkdirID := manager.ProbeIdentificationPair{UID: "MyVFSMkdir2", EBPFFuncName: "kprobe_vfs_mkdir"}
	if err := m3.UpdateActivatedProbes([]manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: mkdirID,
		},
	}); err != nil {
		logrus.Fatal(err)
	}

	vfsOpenID := manager.ProbeIdentificationPair{EBPFFuncName: "kprobe_vfs_opennnnnn"}
	vfsOpenProbe, ok := m3.GetProbe(vfsOpenID)
	if !ok {
		logrus.Fatal("Failed to find kprobe_vfs_opennnnnn")
	}

	if vfsOpenProbe.Enabled {
		logrus.Errorf("kprobe_vfs_opennnnnn should not be enabled")
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
