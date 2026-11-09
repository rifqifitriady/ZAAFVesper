package winevt

import (
	"os"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

func TestCheckProvenance(t *testing.T) {
	raw, err := os.ReadFile("../sysmon/testdata/w01_process_create.xml")
	if err != nil {
		t.Fatal(err)
	}
	sysmonPID := func(pid uint32) bool { return pid == 3160 }
	parse := func(s string) *sysmon.Record {
		r, err := sysmon.Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err := checkProvenance(parse(string(raw)), sysmonPID); err != nil {
		t.Fatalf("genuine event refused: %v", err)
	}
	for name, s := range map[string]string{
		"forged by a user":          strings.Replace(string(raw), `UserID="S-1-5-18"`, `UserID="S-1-5-21-1-2-3-1001"`, 1),
		"forged by another process": strings.Replace(string(raw), `ProcessID="3160"`, `ProcessID="4444"`, 1),
		"no execution element":      strings.Replace(string(raw), `<Execution ProcessID="3160" ThreadID="4120"/>`, "", 1),
		"no security element":       strings.Replace(string(raw), `<Security UserID="S-1-5-18"/>`, "", 1),
	} {
		if err := checkProvenance(parse(s), sysmonPID); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
