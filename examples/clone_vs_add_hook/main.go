package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	manager "github.com/DataDog/ebpf-manager"
)

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

func init() {
	ByteOrder = getHostByteOrder()
}

// getHostByteOrder - Returns the host byte order
func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

//go:embed ebpf/bin/main.o
var Probe []byte

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyFirstHook",
				EBPFFuncName: "kprobe_vfs_mkdir",
			},
			KeepProgramSpec: true,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "",
				EBPFFuncName: "kretprobe_mkdir",
			},
			SyscallFuncName: "mkdir",
			KProbeMaxActive: 100,
		},
	},
	PerfMaps: []*manager.PerfMap{
		{
			Map: manager.Map{
				Name: "my_constants",
			},
			PerfMapOptions: manager.PerfMapOptions{
				DataHandler: myDataHandler,
			},
		},
	},
}

// myDataHandler - Perf event data handler
func myDataHandler(cpu int, data []byte, _ *manager.PerfMap, _ *manager.Manager) {
	myConstant := ByteOrder.Uint64(data[0:8])
	log.Printf("received: CPU:%d my_constant:%d", cpu, myConstant)
}

var editors = []manager.ConstantEditor{
	{
		Name:          "my_constant",
		Value:         uint64(100),
		FailOnMissing: true,
		ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
			{UID: "MyFirstHook", EBPFFuncName: "kprobe_vfs_mkdir"},
		},
	},
	{
		Name:          "my_constant",
		Value:         uint64(555),
		FailOnMissing: true,
		ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
			{UID: "", EBPFFuncName: "kprobe_vfs_mkdir"},
		},
	},
	{
		Name:                     "unused_constant",
		Value:                    uint64(555),
		ProbeIdentificationPairs: []manager.ProbeIdentificationPair{},
	},
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	options := manager.Options{
		ConstantEditors:          editors,
		KeepUnmappedProgramSpecs: true,
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
	log.Println("eBPF programs running, head over to /sys/kernel/debug/tracing/trace_pipe to see them in action.")

	// Demo
	log.Println("INITIAL PROGRAMS")
	if err := trigger(); err != nil {
		return err
	}
	if err := demoClone(); err != nil {
		return err
	}
	if err := demoAddHook(); err != nil {
		return err
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
	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)

	log.Printf("removing %v", tmpDir)
	err = os.RemoveAll(tmpDir)
	if err != nil {
		return fmt.Errorf("rmdir: %s", err)
	}

	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)
	return nil
}
