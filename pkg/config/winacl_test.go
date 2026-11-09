package config

import (
	"strings"
	"testing"
)

func TestWinACLProblem(t *testing.T) {
	users := "S-1-5-32-545"
	authUsers := "S-1-5-11"
	cases := []struct {
		name     string
		owner    string
		hasDACL  bool
		aces     []winACE
		ancestor bool
		want     string // substring; "" = protected
	}{
		{"system owned, admins full", sidSystem, true, []winACE{{Type: 0, Mask: 0x1f01ff, SID: sidAdministrators}, {Type: 0, Mask: 0x1200a9, SID: users}}, false, ""},
		{"user owner", users, true, nil, false, "owned by S-1-5-32-545"},
		{"null dacl", sidAdministrators, false, nil, false, "NULL DACL"},
		{"users modify", sidAdministrators, true, []winACE{{Type: 0, Mask: 0x1301bf, SID: users}}, false, "S-1-5-32-545"},
		{"users generic write", sidAdministrators, true, []winACE{{Type: 0, Mask: genericWrite, SID: users}}, false, "write-like"},
		{"deny entry ignored", sidAdministrators, true, []winACE{{Type: 1, Mask: 0x1f01ff, SID: users}}, false, ""},
		{"inherit-only ignored", sidSystem, true, []winACE{{Type: 0, Flags: aceFlagInheritOnly, Mask: genericAll, SID: "S-1-3-0"}}, false, ""},
		{"owner rights ok", sidSystem, true, []winACE{{Type: 0, Mask: 0x1f01ff, SID: sidOwnerRights}}, false, ""},
		{"object ace without sid", sidSystem, true, []winACE{{Type: 5, Mask: fileWriteData}}, false, "unparsed SID"},
		{"callback allow", sidSystem, true, []winACE{{Type: 9, Mask: rightWriteDAC, SID: users}}, false, "write-like"},
		{"C: root: add subdirectory ok as ancestor", sidTrustedInstaller, true, []winACE{{Type: 0, Mask: fileAppendData, SID: authUsers}}, true, ""},
		{"C: root: add subdirectory refused on target", sidTrustedInstaller, true, []winACE{{Type: 0, Mask: fileAppendData, SID: authUsers}}, false, "write-like"},
		{"ancestor delete child refused", sidSystem, true, []winACE{{Type: 0, Mask: fileDeleteChild, SID: users}}, true, "write-like"},
		{"read only users", sidSystem, true, []winACE{{Type: 0, Mask: 0x1200a9, SID: users}}, false, ""},
		{"unknown ace type with write", sidSystem, true, []winACE{{Type: 0x42, Mask: fileWriteData, SID: users}}, false, "unknown type"},
		{"unknown ace type read only", sidSystem, true, []winACE{{Type: 0x42, Mask: 0x1200a9, SID: users}}, false, ""},
		{"mandatory label ignored", sidSystem, true, []winACE{{Type: 0x11, Mask: 0x1, SID: "S-1-16-12288"}}, false, ""},
	}
	for _, c := range cases {
		got := winACLProblem(c.owner, c.hasDACL, c.aces, c.ancestor)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
