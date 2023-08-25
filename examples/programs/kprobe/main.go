package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "UtimesCommon",
				EBPFFuncName: "kretprobe_utimes_common",
			},
			MatchFuncName:   "utimes",
			KProbeMaxActive: 100,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID: "", // UID is needed only if there are multiple instances of your program (after using
				// m.CloneProgram for example), or if multiple programs with the exact same section are attaching
				// at the exact same hook point (using m.AddHook for example, or simply because another manager
				// on the system is planning on hooking there).
				EBPFFuncName: "kretprobe_mkdirat",
			},
			SyscallFuncName: "mkdirat",
		},
	},
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	options := manager.Options{
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
	}
	if err := m.InitWithOptions(bytes.NewReader(Probe), options); err != nil {
		return err
	}
	defer func() {
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()
	if err := m.Start(); err != nil {
		return err
	}

	log.Println("successfully started")
	log.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	log.Println("=> checkout /sys/kernel/debug/tracing/kprobe_events, utimes_common might have become utimes_common.isra.0")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		log.Print(err)
	}

	log.Println("=> Enter to exit")
	_, _ = fmt.Scanln()
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
