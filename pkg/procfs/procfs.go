// Package procfs reads the few /proc files ZAAFVesper needs on Linux:
// /proc/<pid>/stat (parent and start time), exe, cmdline, cwd and status,
// and the boot time in /proc/stat. Every read is bounded. The readers take
// the proc root as a field so the parsing is tested on any platform with a
// fake tree; only Linux uses them for real.
package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// UserHZ is the unit of the start time in /proc/<pid>/stat (clock ticks,
// sysconf(_SC_CLK_TCK)). The kernel reports USER_HZ, which is 100 on every
// architecture ZAAFVesper builds for (amd64, arm64).
const UserHZ = 100

// Read bounds.
const (
	maxStatBytes    = 4 << 10
	maxStatusBytes  = 16 << 10
	maxProcStatSize = 256 << 10
	// MaxCmdlineBytes bounds /proc/<pid>/cmdline (the kernel caps argv
	// at a few MiB; ZAAFVesper keeps the first 64 KiB).
	MaxCmdlineBytes = 64 << 10
	maxArgs         = 1024
)

// ErrDeletedSuffix is the suffix the kernel appends to /proc/<pid>/exe when
// the executable was unlinked after exec.
const deletedSuffix = " (deleted)"

// Stat is the part of /proc/<pid>/stat ZAAFVesper uses.
type Stat struct {
	PID   int32
	Comm  string
	State byte
	PPID  int32
	// StartTicks is the start time in clock ticks since boot (field 22).
	// Together with the pid it names one process incarnation per boot.
	StartTicks uint64
}

// ParseStat parses /proc/<pid>/stat. comm may hold spaces and parentheses,
// so the fields after it are found from the last ')'.
func ParseStat(b []byte) (Stat, error) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open <= 0 || end < open {
		return Stat{}, errors.New("procfs: malformed stat")
	}
	pid, err := strconv.ParseInt(string(bytes.TrimSpace(b[:open])), 10, 32)
	if err != nil {
		return Stat{}, fmt.Errorf("procfs: stat pid: %w", err)
	}
	rest := strings.Fields(string(b[end+1:]))
	// rest[0] is field 3 (state); field n is rest[n-3].
	if len(rest) < 20 || len(rest[0]) != 1 {
		return Stat{}, errors.New("procfs: short stat")
	}
	ppid, err := strconv.ParseInt(rest[1], 10, 32)
	if err != nil {
		return Stat{}, fmt.Errorf("procfs: stat ppid: %w", err)
	}
	start, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return Stat{}, fmt.Errorf("procfs: stat starttime: %w", err)
	}
	return Stat{PID: int32(pid), Comm: string(b[open+1 : end]), State: rest[0][0], PPID: int32(ppid), StartTicks: start}, nil
}

// ParseBootTime returns the "btime" line of /proc/stat (Unix seconds).
func ParseBootTime(b []byte) (int64, error) {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, errors.New("procfs: no btime in /proc/stat")
}

// StartTime converts a start time in ticks since boot to wall time. btime
// has a resolution of one second, so the result is only good to about a
// second; ZAAFVesper compares ticks (exact) for identity and uses this only
// for display and for the coarse check against an event's time.
func StartTime(btime int64, ticks uint64) time.Time {
	return time.Unix(btime, 0).Add(time.Duration(ticks) * (time.Second / UserHZ)).UTC()
}

// FS reads a proc tree rooted at Root ("/proc" on Linux).
type FS struct{ Root string }

// Default is the real /proc.
var Default = FS{Root: "/proc"}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return b[:max], errTruncated
	}
	return b, nil
}

var errTruncated = errors.New("procfs: truncated")

func (fs FS) pidPath(pid int32, name string) string {
	return filepath.Join(fs.Root, strconv.Itoa(int(pid)), name)
}

// Stat reads /proc/<pid>/stat.
func (fs FS) Stat(pid int32) (Stat, error) {
	b, err := readBounded(fs.pidPath(pid, "stat"), maxStatBytes)
	if err != nil {
		return Stat{}, err
	}
	st, err := ParseStat(b)
	if err != nil {
		return Stat{}, err
	}
	if st.PID != pid {
		return Stat{}, fmt.Errorf("procfs: stat of %d names pid %d", pid, st.PID)
	}
	return st, nil
}

// BootTime reads btime from /proc/stat.
func (fs FS) BootTime() (int64, error) {
	b, err := readBounded(filepath.Join(fs.Root, "stat"), maxProcStatSize)
	if err != nil && !errors.Is(err, errTruncated) {
		return 0, err
	}
	return ParseBootTime(b)
}

// Exe returns the target of /proc/<pid>/exe and whether the kernel marked
// it deleted (unlinked after exec; the suffix is removed from the path).
func (fs FS) Exe(pid int32) (path string, deleted bool, err error) {
	p, err := os.Readlink(fs.pidPath(pid, "exe"))
	if err != nil {
		return "", false, err
	}
	if s, ok := strings.CutSuffix(p, deletedSuffix); ok {
		return s, true, nil
	}
	return p, false, nil
}

// Cwd returns the target of /proc/<pid>/cwd.
func (fs FS) Cwd(pid int32) (string, error) {
	return os.Readlink(fs.pidPath(pid, "cwd"))
}

// Cmdline returns argv from /proc/<pid>/cmdline (NUL separated), at most
// MaxCmdlineBytes and maxArgs entries; truncated reports a cut.
func (fs FS) Cmdline(pid int32) (args []string, truncated bool, err error) {
	b, err := readBounded(fs.pidPath(pid, "cmdline"), MaxCmdlineBytes)
	if errors.Is(err, errTruncated) {
		truncated, err = true, nil
	}
	if err != nil {
		return nil, false, err
	}
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil, truncated, nil
	}
	for _, a := range bytes.Split(b, []byte{0}) {
		if len(args) == maxArgs {
			return args, true, nil
		}
		args = append(args, string(a))
	}
	return args, truncated, nil
}

// UIDs returns the real and effective uid from /proc/<pid>/status.
func (fs FS) UIDs(pid int32) (real, effective int64, err error) {
	b, err := readBounded(fs.pidPath(pid, "status"), maxStatusBytes)
	if err != nil && !errors.Is(err, errTruncated) {
		return -1, -1, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) < 2 {
				break
			}
			r, err1 := strconv.ParseInt(f[0], 10, 64)
			e, err2 := strconv.ParseInt(f[1], 10, 64)
			if err1 != nil || err2 != nil {
				break
			}
			return r, e, nil
		}
	}
	return -1, -1, errors.New("procfs: no Uid line in status")
}

// PIDs lists the numeric entries of the proc root.
func (fs FS) PIDs() ([]int32, error) {
	ents, err := os.ReadDir(fs.Root)
	if err != nil {
		return nil, err
	}
	out := make([]int32, 0, len(ents))
	for _, e := range ents {
		n, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil || n <= 0 {
			continue
		}
		out = append(out, int32(n))
	}
	return out, nil
}
