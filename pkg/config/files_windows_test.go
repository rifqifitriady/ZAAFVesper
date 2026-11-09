//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckOwnershipWindows: a file in the user's temp folder is owned by
// the user (refused); the hosts file is SYSTEM/Administrators-owned and only
// readable by Users (accepted).
func TestCheckOwnershipWindows(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(0, f); err == nil {
		t.Fatal("user-owned file accepted")
	}
	hosts := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	if err := checkOwnership(0, hosts); err != nil {
		t.Fatalf("hosts refused: %v", err)
	}
}
