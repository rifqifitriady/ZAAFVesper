//go:build linux

package response

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vaultCount is the number of entries in the vault directory (0 when it
// was never created).
func vaultCount(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// Dry-run remove_persistence on Linux: no runner call (no systemctl show,
// disable or daemon-reload), the file stays with its content, nothing is
// stored in the vault and nothing is queued for retry. The shared dry-run
// tests are darwin-only, so CI never ran this branch on Linux (CK-09).
func TestLinuxRemovePersistenceDryRun(t *testing.T) {
	for _, c := range []struct{ name, rel, kind string }{
		{"systemd unit", "etc/systemd/system/evil.service", "systemd unit"},
		{"cron file", "etc/cron.d/evil", "cron file"},
		{"shell rc file", "home/bob/.bashrc", "shell rc file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newLRig(t, true)
			g.run = func(string, []string) ([]byte, error) { // would be reached by a real stop
				return []byte(filepath.Join(g.dir, c.rel) + "\n"), nil
			}
			p := filepath.Join(g.dir, c.rel)
			b := write(t, p, "evil-content")
			err := g.r.RemovePersistence(fileEvent(t, p, b, "/tmp/dropper", ""), "r", "r")
			d := g.last()
			if err != nil || d.Outcome != OutcomeDryRun || !strings.Contains(d.Detail, "would move the "+c.kind) {
				t.Fatalf("%v %+v", err, d)
			}
			if len(g.cmds) != 0 {
				t.Fatalf("dry-run ran %q", g.cmds)
			}
			if got, rerr := os.ReadFile(p); rerr != nil || string(got) != "evil-content" {
				t.Fatalf("file changed: %q %v", got, rerr)
			}
			if n := vaultCount(t, g.r.cfg.VaultDir); n != 0 {
				t.Fatalf("%d vault entries", n)
			}
			if g.r.Retries() != 0 {
				t.Fatalf("retries=%d", g.r.Retries())
			}
		})
	}
}

// A dry-run isolate on Linux runs no nft command and records no state.
func TestLinuxIsolateDryRun(t *testing.T) {
	g := newLRig(t, true)
	g.r.Observe(netEv("192.0.2.7"))
	_ = g.r.IsolateProcess(netEv("192.0.2.7"), TargetProcess, "r", "r")
	if g.last().Outcome != OutcomeDryRun || len(g.cmds) != 0 || len(g.stdins) != 0 {
		t.Fatalf("%+v %q", g.last(), g.cmds)
	}
}

// resolvConfFiles: the union of /etc/resolv.conf and systemd-resolved's
// file. On Ubuntu the first lists only the stub 127.0.0.53; the real
// resolvers are in the second and must be in the never-block set (CK-34).
func TestLinuxResolverUnionUbuntuStub(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "resolv.conf")
	sys := filepath.Join(dir, "systemd-resolv.conf")
	if err := os.WriteFile(etc, []byte("# stub\nnameserver 127.0.0.53\noptions edns0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sys, []byte("nameserver 10.1.2.3\nnameserver 2001:db8::53\nsearch example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := resolvConfFiles
	defer func() { resolvConfFiles = old }()

	resolvConfFiles = []string{etc, sys}
	got := defaultResolvers()
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("2001:db8::53")}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}

	// One file missing: the other still counts, no error.
	resolvConfFiles = []string{filepath.Join(dir, "absent"), sys}
	if got := defaultResolvers(); len(got) != 2 || got[0] != want[1] {
		t.Fatalf("missing first file: %v", got)
	}
	resolvConfFiles = []string{etc, filepath.Join(dir, "absent")}
	if got := defaultResolvers(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("missing second file: %v", got)
	}

	// The union feeds the never-block set: the real resolver is not
	// blockable, an unrelated address is.
	resolvConfFiles = []string{etc, sys}
	g := newLRig(t, false)
	g.r.cfg.Resolvers = defaultResolvers
	nb, err := g.r.neverBlock()
	if err != nil {
		t.Fatal(err)
	}
	if why := g.r.blockable(netip.MustParseAddr("10.1.2.3"), nb); why != "a DNS resolver of this host" {
		t.Fatalf("systemd-resolved resolver: %q", why)
	}
	if why := g.r.blockable(netip.MustParseAddr("2001:db8::53"), nb); why != "a DNS resolver of this host" {
		t.Fatalf("v6 resolver: %q", why)
	}
	if why := g.r.blockable(netip.MustParseAddr("192.0.2.7"), nb); why != "" {
		t.Fatalf("unrelated address: %q", why)
	}
	g.r.Observe(netEv("10.1.2.3"))
	_ = g.r.IsolateProcess(netEv("192.0.2.7"), TargetProcess, "r", "r")
	if d := g.last(); d.Outcome != OutcomeIsolated || strings.Contains(strings.Join(g.stdins, ""), "10.1.2.3") {
		t.Fatalf("%+v %q", d, g.stdins)
	}
}

// Network and FUSE file systems are refused by isLocalFS and so by
// quarantine_file (CK-42). fstatfs is injected: no mount is needed.
func TestLinuxRemoteFSRefused(t *testing.T) {
	// Every listed type is remote; an ordinary local type is not.
	old := fstatfs
	defer func() { fstatfs = old }()
	for typ, name := range remoteFS {
		fstatfs = func(_ int, st *unixStatfs) error { st.Type = typ; return nil }
		if local, err := isLocalFS(0); err != nil || local {
			t.Errorf("%s (%#x): local=%v err=%v", name, typ, local, err)
		}
	}
	fstatfs = func(_ int, st *unixStatfs) error { st.Type = 0xEF53; return nil } // ext4
	if local, err := isLocalFS(0); err != nil || !local {
		t.Errorf("ext4: local=%v err=%v", local, err)
	}
	fstatfs = func(int, *unixStatfs) error { return os.ErrPermission }
	if local, err := isLocalFS(0); err == nil || local {
		t.Errorf("statfs error: local=%v err=%v", local, err)
	}

	// End to end: a file on an "NFS" mount is not quarantined.
	g := newLRig(t, false)
	p := filepath.Join(g.dir, "f")
	b := write(t, p, "x")
	fstatfs = func(_ int, st *unixStatfs) error { st.Type = 0x6969; return nil }
	_ = g.r.QuarantineFile(fileEvent(t, p, b, "/tmp/evil", ""), TargetFile, "r", "r")
	if d := g.last(); d.Outcome != OutcomeFileCheck || !strings.Contains(d.Detail, "not on a local file system") || !exists(p) {
		t.Fatalf("%+v", d)
	}
	if vaultCount(t, g.r.cfg.VaultDir) != 0 {
		t.Fatal("vault entry for a refused file")
	}
}
