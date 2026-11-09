//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestIgnoreJobControlSignals(t *testing.T) {
	sigs := []os.Signal{syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU}
	defer signal.Reset(sigs...)
	ignoreJobControlSignals()
	for _, s := range sigs {
		if !signal.Ignored(s) {
			t.Fatalf("%v not ignored", s)
		}
	}
	if signal.Ignored(syscall.SIGTERM) || signal.Ignored(syscall.SIGINT) {
		t.Fatal("SIGTERM/SIGINT must still stop the sensor")
	}
	_ = stdinIsTerminal() // must not panic without a terminal
}
