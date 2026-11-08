package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func chmodACL(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", args...).CombinedOutput(); err != nil {
		t.Fatalf("chmod %v: %v %s", args, err, out)
	}
}

// TestACLs proves that a write-permitting ACL entry on a file or on an
// ancestor directory is rejected while deny-only entries are accepted.
func TestACLs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("ACLs are checked on macOS only")
	}
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	f := filepath.Join(rules, "a.yml")
	write(t, f, "x")
	for _, p := range []string{dir, rules} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkOwnership(uid, rules); err != nil {
		t.Fatalf("clean tree rejected: %v", err)
	}
	// Deny-only entries grant nothing.
	chmodACL(t, "+a", "everyone deny delete,write", f)
	if err := checkOwnership(uid, rules); err != nil {
		t.Fatalf("deny-only ACL rejected: %v", err)
	}
	// A permit entry for a write-like right on the file.
	for _, right := range []string{"write", "append", "delete", "writeattr", "writeextattr", "writesecurity", "chown"} {
		chmodACL(t, "-N", f)
		chmodACL(t, "+a", "everyone allow "+right, f)
		err := checkOwnership(uid, rules)
		if err == nil || !strings.Contains(err.Error(), "a.yml") || !strings.Contains(err.Error(), "ACL") {
			t.Fatalf("allow %s accepted: %v", right, err)
		}
	}
	// Read-only permits are fine.
	chmodACL(t, "-N", f)
	chmodACL(t, "+a", "everyone allow read,readattr", f)
	if err := checkOwnership(uid, rules); err != nil {
		t.Fatalf("read-only ACL rejected: %v", err)
	}
	// SecureRead checks the open descriptor's ACL.
	prev := RequiredOwner()
	defer RequireOwner(prev)
	RequireOwner(int64(uid))
	if _, err := SecureRead(f, 100); err != nil {
		t.Fatalf("SecureRead with read-only ACL: %v", err)
	}
	chmodACL(t, "+a", "everyone allow write", f)
	if _, err := SecureRead(f, 100); err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("SecureRead accepted a write ACL: %v", err)
	}
	chmodACL(t, "-N", f)
	// An ancestor directory with add_file (and an inherit-only entry).
	chmodACL(t, "+a", "everyone allow add_file,file_inherit,only_inherit", dir)
	if err := checkOwnership(uid, f); err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("ancestor ACL accepted: %v", err)
	}
	chmodACL(t, "-N", dir)
	chmodACL(t, "+a", "everyone allow delete_child", rules)
	if err := checkOwnership(uid, f); err == nil {
		t.Fatal("delete_child on parent accepted")
	}
	chmodACL(t, "-N", rules)
	if err := checkOwnership(uid, rules); err != nil {
		t.Fatalf("after chmod -N: %v", err)
	}
}

func TestWritePermitACEParse(t *testing.T) {
	if why, err := writePermitACE(nil); why != "" || err != nil {
		t.Fatal("empty filesec")
	}
	if _, err := writePermitACE(make([]byte, 10)); err == nil {
		t.Fatal("short filesec accepted")
	}
	b := make([]byte, filesecHeader+aclHeader)
	b[0], b[1], b[2], b[3] = 0x6d, 0xc1, 0x2c, 0x01
	b[filesecHeader] = 5 // claims 5 entries, has none
	if _, err := writePermitACE(b); err == nil {
		t.Fatal("truncated ACL accepted")
	}
	for i := 0; i < 4; i++ {
		b[filesecHeader+i] = 0xff // KAUTH_FILESEC_NOACL
	}
	if why, err := writePermitACE(b); why != "" || err != nil {
		t.Fatalf("NOACL: %q %v", why, err)
	}
}
