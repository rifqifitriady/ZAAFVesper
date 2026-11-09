package procfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	// comm with spaces and a ')' inside, as a process can name itself.
	b := []byte("4242 (evil) (x y) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n")
	st, err := ParseStat(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != 4242 || st.PPID != 17 || st.StartTicks != 98765 || st.Comm != "evil) (x y" || st.State != 'S' {
		t.Fatalf("got %+v", st)
	}
	for _, bad := range []string{"", "12", "12 (x", "x (y) S 1 2", "1 (a) S z 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"} {
		if _, err := ParseStat([]byte(bad)); err == nil {
			t.Errorf("ParseStat(%q) accepted", bad)
		}
	}
}

func TestBootAndStart(t *testing.T) {
	bt, err := ParseBootTime([]byte("cpu  1 2 3\nbtime 1700000000\nprocesses 5\n"))
	if err != nil || bt != 1700000000 {
		t.Fatalf("btime %d %v", bt, err)
	}
	got := StartTime(bt, 250)
	if want := time.Unix(1700000002, 500*int64(time.Millisecond)).UTC(); !got.Equal(want) {
		t.Fatalf("StartTime = %v, want %v", got, want)
	}
}

func TestFSReaders(t *testing.T) {
	root := t.TempDir()
	pd := filepath.Join(root, "77")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(pd, "stat"), []byte("77 (sh) R 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0"), 0o644))
	must(os.WriteFile(filepath.Join(pd, "cmdline"), []byte("/bin/sh\x00-c\x00echo hi\x00"), 0o644))
	must(os.WriteFile(filepath.Join(pd, "status"), []byte("Name:\tsh\nUid:\t1000\t0\t0\t0\n"), 0o644))
	must(os.Symlink("/usr/bin/dash (deleted)", filepath.Join(pd, "exe")))
	must(os.WriteFile(filepath.Join(root, "stat"), []byte("btime 100\n"), 0o644))
	must(os.Mkdir(filepath.Join(root, "self"), 0o755))
	fs := FS{Root: root}
	st, err := fs.Stat(77)
	if err != nil || st.StartTicks != 500 || st.PPID != 1 {
		t.Fatalf("Stat %+v %v", st, err)
	}
	if _, err := fs.Stat(78); err == nil {
		t.Fatal("missing pid read")
	}
	args, trunc, err := fs.Cmdline(77)
	if err != nil || trunc || len(args) != 3 || args[2] != "echo hi" {
		t.Fatalf("Cmdline %q %v %v", args, trunc, err)
	}
	r, e, err := fs.UIDs(77)
	if err != nil || r != 1000 || e != 0 {
		t.Fatalf("UIDs %d %d %v", r, e, err)
	}
	exe, del, err := fs.Exe(77)
	if err != nil || !del || exe != "/usr/bin/dash" {
		t.Fatalf("Exe %q %v %v", exe, del, err)
	}
	bt, err := fs.BootTime()
	if err != nil || bt != 100 {
		t.Fatalf("BootTime %d %v", bt, err)
	}
	pids, err := fs.PIDs()
	if err != nil || len(pids) != 1 || pids[0] != 77 {
		t.Fatalf("PIDs %v %v", pids, err)
	}
}
