package manager

import (
	"debug/elf"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateEventName(t *testing.T) {
	probeType := "p"
	funcName := "func"
	UID := "UID"
	kprobeAttachPID := 1234

	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		t.Error(err)
	}
	if len(eventName) > MaxEventNameLen {
		t.Errorf("Event name too long, kernel limit is %d : MaxEventNameLen", MaxEventNameLen)
	}

	// should be truncated
	funcName = "01234567890123456790123456789012345678901234567890123456789"
	eventName, err = GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if (err != nil) || (len(eventName) != MaxEventNameLen) || (eventName != "p_01234567890123456790123456789012345678901234567890123_UID_1234") {
		t.Errorf("Should not failed and truncate the function name (len %d)", len(eventName))
	}

	UID = "12345678901234567890123456789012345678901234567890"
	_, err = GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err == nil {
		t.Errorf("Test should failed as event name length is too big for the kernel and free space for function Name is < %d", MinFunctionNameLen)
	}
}

// return "/usr/lib/ld-linux-x86-64.so.2" for example
func detectLDLoaderPath(t *testing.T) (string, error) {
	out, err := exec.Command("bash", "-c", `grep '/ld-.*\.so.*$' /proc/self/maps | head -n1 | awk '{print $6}'`).Output()
	if err != nil {
		return "", err
	}
	return string(out[:len(out)-1]), nil
}

func openAndListSymbols(t *testing.T, path string) ([]elf.Symbol, error) {
	f, sym, err := OpenAndListSymbols(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sym, nil
}

func openAndListSymbolsFromPID(t *testing.T, path string) ([]elf.Symbol, error) {
	f, sym, err := OpenAndListSymbolsFromPID(os.Getpid(), path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sym, nil
}

func TestOpenAndListSymbols(t *testing.T) {
	path, err := detectLDLoaderPath(t)
	require.NoError(t, err)

	syms, err := openAndListSymbols(t, path)
	require.NoError(t, err)
	require.True(t, len(syms) > 0)

	t.Log("NR symbol loaded:", len(syms))
}

func TestOpenAndListSymbolsFromPID(t *testing.T) {
	path, err := detectLDLoaderPath(t)
	require.NoError(t, err)

	syms, err := openAndListSymbolsFromPID(t, path)
	require.NoError(t, err)
	require.True(t, len(syms) > 0)

	t.Log("NR symbol loaded:", len(syms))
}

func TestCheckIfAllMemorySymbolMatchLibrary(t *testing.T) {
	path, err := detectLDLoaderPath(t)
	require.NoError(t, err)

	symsFromLib, err := openAndListSymbols(t, path)
	require.NoError(t, err)
	require.True(t, len(symsFromLib) > 0)
	symsFromMem, err := openAndListSymbolsFromPID(t, path)
	require.NoError(t, err)
	require.True(t, len(symsFromMem) > 0)

	/* memory file report only dynamic symbol */
	m := make(map[string]elf.Symbol)
	for _, s := range symsFromMem {
		if _, ok := m[s.Name]; ok {
			t.Fatal("library symbol collision")
		}
		m[s.Name] = s
	}

	symFound := make(map[string]bool)
	for _, s := range symsFromLib {
		if _, ok := m[s.Name]; ok {
			if s.Value != m[s.Name].Value {
				t.Fatalf("symbol address/offset missmatch %v %v\t%s", s.Value, m[s.Name].Value, s.Name)
			}
			symFound[s.Name] = true
		}
	}
	if len(m) != len(symFound) {
		t.Error("can't resolve symbol from memory (memory ELF vs library ELF file")
	}
}
