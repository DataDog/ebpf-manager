package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := run1(); err != nil {
		return err
	}

	log.Println("=> Enter to continue")
	_, _ = fmt.Scanln()

	if err := run2(); err != nil {
		return err
	}

	log.Println("=> Enter to continue")
	_, _ = fmt.Scanln()

	if err := run3(); err != nil {
		return err
	}
	return nil
}

func run1() error {
	if err := m1.InitWithOptions(bytes.NewReader(Probe), options1); err != nil {
		return err
	}
	defer func() {
		if err := m1.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	oldID := manager.ProbeIdentificationPair{
		EBPFFuncName: "kprobe_exclude",
		UID:          "",
	}
	newID := manager.ProbeIdentificationPair{
		EBPFFuncName: "kprobe_exclude",
		UID:          "new",
	}
	if err := m1.RenameProbeIdentificationPair(oldID, newID); err != nil {
		return err
	}
	_, ok := m1.GetProbe(newID)
	if !ok {
		return fmt.Errorf("RenameProbeIdentificationPair failed")
	}

	if err := m1.Start(); err != nil {
		return err
	}
	log.Println("m1 successfully started")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		log.Print(err)
	}
	return nil
}

func run2() error {
	log.Println("moving on to m2 (an error is expected)")
	if err := m2.InitWithOptions(bytes.NewReader(Probe), options2); err != nil {
		return err
	}
	defer func() {
		if err := m2.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	if err := m2.Start(); err != nil {
		log.Print(err)
	}
	return nil
}

func run3() error {
	log.Println("moving on to m3 (an error is expected)")
	if err := m3.Init(bytes.NewReader(Probe)); err != nil {
		return err
	}
	defer func() {
		if err := m3.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	if err := m3.Start(); err != nil {
		log.Print(err)
	}

	log.Println("updating activated probes of m3 (no error is expected)")
	if err := m3.Init(bytes.NewReader(Probe)); err != nil {
		return err
	}
	mkdirID := manager.ProbeIdentificationPair{UID: "MyVFSMkdir2", EBPFFuncName: "kprobe_vfs_mkdir"}
	if err := m3.UpdateActivatedProbes([]manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: mkdirID,
		},
	}); err != nil {
		return err
	}

	vfsOpenID := manager.ProbeIdentificationPair{EBPFFuncName: "kprobe_vfs_opennnnnn"}
	vfsOpenProbe, ok := m3.GetProbe(vfsOpenID)
	if !ok {
		return fmt.Errorf("failed to find kprobe_vfs_opennnnnn")
	}

	if vfsOpenProbe.Enabled {
		return fmt.Errorf("kprobe_vfs_opennnnnn should not be enabled")
	}
	return nil
}

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	log.Println("Generating events to trigger the probes ...")
	tmpDir, err := os.MkdirTemp("", "example")
	if err != nil {
		return fmt.Errorf("mkdirtmp: %s", err)
	}
	log.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
