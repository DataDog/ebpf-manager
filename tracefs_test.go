package manager

import (
	"runtime"
	"testing"
)

func BenchmarkFindFilterFunction(b *testing.B) {
	var needle string
	switch runtime.GOARCH {
	case "arm64":
		needle = "__arm64_sys_open"
	default:
		needle = "__x64_sys_open"
	}

	for i := 0; i < b.N; i++ {
		_, err := FindFilterFunction(needle)
		if err != nil {
			b.Error(err)
		}
	}
}
