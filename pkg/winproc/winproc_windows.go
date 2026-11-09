//go:build windows

package winproc

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessCritical = kernel32.NewProc("IsProcessCritical")
)

// Entry is one process of a Toolhelp32 snapshot.
type Entry struct {
	PID, PPID uint32
	ExeFile   string // base name only (PROCESSENTRY32W.szExeFile)
}

// Snapshot lists the running processes (CreateToolhelp32Snapshot).
func Snapshot() ([]Entry, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(h)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []Entry
	for err = windows.Process32First(h, &pe); err == nil; err = windows.Process32Next(h, &pe) {
		out = append(out, Entry{PID: pe.ProcessID, PPID: pe.ParentProcessID, ExeFile: windows.UTF16ToString(pe.ExeFile[:])})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, fmt.Errorf("Process32Next: %w", err)
	}
	return out, nil
}

// Open opens pid with the given access rights.
func Open(pid uint32, access uint32) (windows.Handle, error) {
	return windows.OpenProcess(access, false, pid)
}

// OpenQuery opens pid with PROCESS_QUERY_LIMITED_INFORMATION.
func OpenQuery(pid uint32) (windows.Handle, error) {
	return Open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
}

// CreationTime returns the creation time of the process behind h as a raw
// FILETIME (100 ns since 1601: the per-boot incarnation stamp ZAAFVesper
// compares) and as a time.
func CreationTime(h windows.Handle) (uint64, time.Time, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, time.Time{}, fmt.Errorf("GetProcessTimes: %w", err)
	}
	ft := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	if ft == 0 {
		return 0, time.Time{}, errors.New("GetProcessTimes: zero creation time")
	}
	return ft, FiletimeToTime(ft), nil
}

// ImagePath returns the Win32 path of the process image
// (QueryFullProcessImageNameW).
func ImagePath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", fmt.Errorf("QueryFullProcessImageName: %w", err)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// IsCritical reports whether the process is marked critical (terminating it
// stops Windows with a bug check). Needs Windows 8.1 or later.
func IsCritical(h windows.Handle) (bool, error) {
	if err := procIsProcessCritical.Find(); err != nil {
		return false, err
	}
	var crit int32
	r, _, err := procIsProcessCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&crit)))
	if r == 0 {
		return false, fmt.Errorf("IsProcessCritical: %w", err)
	}
	return crit != 0, nil
}

// maxCmdlineBytes bounds the command line read (UTF-16 bytes).
const maxCmdlineBytes = 64 << 10

// CommandLine reads the command line of the process behind h
// (NtQueryInformationProcess ProcessCommandLineInformation, Windows 8.1+).
// h needs PROCESS_QUERY_LIMITED_INFORMATION.
func CommandLine(h windows.Handle) (string, error) {
	buf := make([]byte, int(unsafe.Sizeof(windows.NTUnicodeString{}))+maxCmdlineBytes)
	var ret uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buf[0]), uint32(len(buf)), &ret); err != nil {
		return "", fmt.Errorf("NtQueryInformationProcess: %w", err)
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return "", nil
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	start := uintptr(unsafe.Pointer(us.Buffer))
	if start < base || start+uintptr(us.Length) > base+uintptr(len(buf)) {
		return "", errors.New("NtQueryInformationProcess: command line outside the buffer")
	}
	off := int(start - base)
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), int(us.Length)/2)
	return windows.UTF16ToString(u16), nil
}
