package manager

import (
	"bytes"
	"testing"
)

func TestGenerateEventName(t *testing.T) {
	probeType := "p"
	funcName := "func"
	UID := "UID"
	kprobeAttachPID := 1234

	eventName, err := generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		t.Error(err)
	}
	if len(eventName) > maxEventNameLen {
		t.Errorf("Event name too long, kernel limit is %d : maxEventNameLen", maxEventNameLen)
	}

	// should be truncated
	funcName = "01234567890123456790123456789012345678901234567890123456789"
	eventName, err = generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if (err != nil) || (len(eventName) != maxEventNameLen) || (eventName != "p_01234567890123456790123456789012345678901234567890123_UID_1234") {
		t.Errorf("Should not failed and truncate the function name (len %d)", len(eventName))
	}

	UID = "12345678901234567890123456789012345678901234567890"
	_, err = generateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err == nil {
		t.Errorf("Test should failed as event name length is too big for the kernel and free space for function Name is < %d", minFunctionNameLen)
	}
}

func TestGetSyscallFnNameWithKallsyms(t *testing.T) {
	kallsymsContent := `
0000000000000000 T do_fchownat
0000000000000000 T __arm64_sys_fchownat
0000000000000000 T __arm64_sys_chown
0000000000000000 T __arm64_sys_lchown
0000000000000000 T vfs_fchown
0000000000000000 T ksys_fchown
0000000000000000 T __arm64_sys_fchown
0000000000000000 T vfs_open
0000000000000000 T build_open_how
0000000000000000 T build_open_flags
0000000000000000 t do_sys_openat2
0000000000000000 t __do_sys_openat2
0000000000000000 T __arm64_sys_openat2
0000000000000000 T __arm64_sys_creat
0000000000000000 T __arm64_compat_sys_open
0000000000000000 T __arm64_compat_sys_openat
0000000000000000 T __arm64_sys_open
0000000000000000 T __arm64_sys_openat
0000000000000000 T file_open_name
0000000000000000 T do_sys_open
0000000000000000 T vfs_setpos
0000000000000000 T generic_file_llseek_size
0000000000000000 T generic_file_llseek
0000000000000000 T fixed_size_llseek
0000000000000000 T no_seek_end_llseek
0000000000000000 T no_seek_end_llseek_size
0000000000000000 T noop_llseek
0000000000000000 T vfs_llseek
0000000000000000 T default_llseek
0000000000000000 t arch_local_irq_save
	`

	res, err := getSyscallFnNameWithKallsyms("open", bytes.NewBuffer([]byte(kallsymsContent)), "arm64")
	if err != nil {
		t.Fatal(err)
	}

	expected := "__arm64_sys_open"
	if res != expected {
		t.Errorf("expected %s, got %s", expected, res)
	}
}
