//go:build darwin

package ps

import (
	"os"
	"testing"
)

// TestKernelReadersLive checks the proc_info / csops layouts on this Mac:
// p_puniqueid of this process is p_uniqueid of its parent, p_idversion is
// non-zero, launchd is unique id 1 and a platform binary. Pure Go: also
// runs with CGO_ENABLED=0.
func TestKernelReadersLive(t *testing.T) {
	id, pv, err := readUniqueIdentifiers(int32(os.Getpid()))
	if err != nil || id == 0 || pv == 0 {
		t.Fatalf("self: id %d pv %d err %v", id, pv, err)
	}
	if got, err := ReadUniqueID(int32(os.Getpid())); err != nil || got != id {
		t.Fatalf("ReadUniqueID = %d, %v", got, err)
	}
	if l, err := ReadUniqueID(1); err != nil || l != 1 {
		t.Errorf("launchd unique id %d, %v", l, err)
	}
	if plat, err := readPlatform(1); err != nil || !plat {
		t.Errorf("launchd platform %v, %v", plat, err)
	}
	if _, err := ReadUniqueID(99999999); err == nil {
		t.Error("nonexistent pid read")
	}
	// Bootstrap (live mode) records unique ids and kernel platform flags.
	s := NewSnapshotter(true)
	if p, ok := s.Lookup(int32(os.Getpid())); !ok || p.UniqueID != id || !p.Seeded {
		t.Errorf("seeded self: %+v", p)
	}
	if p, ok := s.Lookup(1); !ok || !p.IsPlatform || p.UniqueID != 1 {
		t.Errorf("seeded launchd: platform %v id %d", p.IsPlatform, p.UniqueID)
	}
}
