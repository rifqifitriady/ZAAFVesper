//go:build unix

package nofollow

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrLink) {
		t.Fatalf("Open(link) = %v, want ErrLink", err)
	}
	f, err := Open(real)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}
