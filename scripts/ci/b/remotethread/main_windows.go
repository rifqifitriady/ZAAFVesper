//go:build windows

// Command remotethread is a test helper for the live Windows validation: it
// starts ping.exe, creates one thread in it that starts at
// kernel32!ExitThread (so the thread does nothing but end), waits, then ends
// ping. Run from a user-writable folder, it exercises the rule "Remote
// thread created in another process from a user-writable location" (Sysmon
// event 8) without injecting any code.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "remotethread:", err)
		os.Exit(1)
	}
}

func run() error {
	ping := exec.Command("ping.exe", "-n", "30", "127.0.0.1")
	if err := ping.Start(); err != nil {
		return err
	}
	defer ping.Process.Kill()
	time.Sleep(time.Second)
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	exitThread := k32.NewProc("ExitThread")
	createRemoteThread := k32.NewProc("CreateRemoteThread")
	if err := exitThread.Find(); err != nil {
		return err
	}
	// kernel32.dll is mapped at the same address in every process of a
	// boot, so ExitThread's address here is valid in ping.exe too.
	h, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ, false, uint32(ping.Process.Pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)
	th, _, cerr := createRemoteThread.Call(uintptr(h), 0, 0, exitThread.Addr(), 0, 0, 0)
	if th == 0 {
		return fmt.Errorf("CreateRemoteThread: %v", cerr)
	}
	windows.WaitForSingleObject(windows.Handle(th), 5000)
	windows.CloseHandle(windows.Handle(th))
	fmt.Printf("created a thread in ping.exe (pid %d) at ExitThread\n", ping.Process.Pid)
	time.Sleep(2 * time.Second)
	return nil
}
