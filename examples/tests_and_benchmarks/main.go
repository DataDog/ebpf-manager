package main

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed ebpf/bin/probe.o
var Probe []byte

type TestData struct {
	Input  uint32
	Output uint32
}

func (td TestData) String() string {
	return fmt.Sprintf("{ Input:%v Output:%v }", td.Input, td.Output)
}

var testDataKey = uint32(1)

var testData = []TestData{
	{2, 4},
	{10, 20},
	{42, 128},
	{42, 84},
}

func main() {
	// Initialize the manager
	var m = &manager.Manager{}
	if err := m.Init(bytes.NewReader(Probe)); err != nil {
		logrus.Fatal(err)
	}

	// Get map used to send tests
	testMap, found, err := m.GetMap("my_func_test_data")
	if !found || err != nil {
		logrus.Fatalf("couldn't retrieve my_func_test_data %v", err)
	}

	// Get xdp program used to trigger the tests
	testProgs, found, err := m.GetProgram(
		manager.ProbeIdentificationPair{
			EBPFFuncName: "my_func_test",
		},
	)
	if !found || err != nil {
		logrus.Fatalf("couldn't retrieve my_func_test %v", err)
	}
	testProg := testProgs[0]

	// Run test
	runtTest(testMap, testProg)

	// Run benchmark
	runtBenchmark(testMap, testProg)
}

func runtTest(testMap *ebpf.Map, testProg *ebpf.Program) {
	logrus.Println("Running tests ...")
	for _, data := range testData {
		// insert data
		if err := testMap.Put(testDataKey, data); err != nil {
			logrus.Fatal(err)
		}

		// Trigger test - (the 14 bytes is for the minimum packet size required to test an XDP program)
		outLen, _, err := testProg.Test(make([]byte, 14))
		if err != nil {
			logrus.Fatal(err)
		}
		if data.Input == 42 && data.Output == 128 {
			logrus.Printf("(failure expected on next test)")
		}
		if outLen == 0 {
			logrus.Printf("%v - PASS", data)
		} else {
			logrus.Printf("%v - FAIL (checkout /sys/kernel/debug/tracing/trace_pipe to see the logs)", data)
		}
	}
}

func runtBenchmark(testMap *ebpf.Map, testProg *ebpf.Program) {
	logrus.Println("Running benchmark ...")
	for _, data := range testData {
		// insert data
		if err := testMap.Put(testDataKey, data); err != nil {
			logrus.Fatal(err)
		}

		// Trigger test
		outLen, duration, err := testProg.Benchmark(make([]byte, 14), 1000, nil)
		if err != nil {
			logrus.Fatal(err)
		}
		if data.Input == 42 && data.Output == 128 {
			logrus.Printf("(failure expected on next benchmark)")
		}
		if outLen == 0 {
			logrus.Printf("%v - PASS (duration: %v)", data, duration)
		} else {
			logrus.Printf("%v - benchmark FAILED (checkout /sys/kernel/debug/tracing/trace_pipe to see the logs)", data)
		}
	}
}
