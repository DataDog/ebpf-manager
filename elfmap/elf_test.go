package elfmap

import (
	"bytes"
	"debug/elf"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ElfSymbols(t *testing.T, path string) []elf.Symbol {
	/* debug/ELF loader */
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	expectedSyms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	expectedSyms = append(expectedSyms, dynSyms...)
	if len(expectedSyms) == 0 {
		t.Error("Symbol list is empty")
	}
	return expectedSyms
}

func ElfMapSymbols(t *testing.T, path string) []elf.Symbol {
	/* ELFMap loader */
	fmap, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fmap.Close()

	syms, err := fmap.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	dynSyms, err := fmap.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		t.Error("Symbol list is empty")
	}
	return syms
}

func ElfMapSymbolsMapBytes(t *testing.T, path string) []elf.Symbol {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	/* fake the rebuild of /proc/pid/maps library section */
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	/* ELFMap loader */
	fmap, err := OpenMapBytes(bytes.NewReader(b), 0 /* vBaseAddr */)
	if err != nil {
		t.Fatal(err)
	}
	defer fmap.Close()

	syms, err := fmap.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	dynSyms, err := fmap.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		t.Error("Symbol list is empty")
	}
	return syms
}

func TestOpenListAndSymbols(t *testing.T) {
	path := "/lib64/ld-linux-x86-64.so.2"
	expectedSyms := ElfSymbols(t, path)
	syms := ElfMapSymbols(t, path)
	assert.ElementsMatch(t, expectedSyms, syms)
}

func TestOpenListAndSymbolsMapBytes(t *testing.T) {
	path := "/lib64/ld-linux-x86-64.so.2"
	expectedSyms := ElfSymbols(t, path)
	syms := ElfMapSymbolsMapBytes(t, path)
	assert.ElementsMatch(t, expectedSyms, syms)
}
