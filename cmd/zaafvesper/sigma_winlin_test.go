package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// The curated SigmaHQ sets for Windows and Linux (workstream S4) are the
// converter's exact output from the originals vendored under
// pkg/sigma/testdata/sigmahq-<platform>, and keep the DRL 1.1 attribution.
func TestShippedSigmaWindowsLinuxRegenerate(t *testing.T) {
	for _, plat := range []string{"windows", "linux"} {
		out := filepath.Join(t.TempDir(), plat)
		rep, err := sigmaConvert("../../pkg/sigma/testdata/sigmahq-"+plat, out, false)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Summary.Skipped != 0 || rep.Summary.Errors != 0 {
			t.Fatalf("%s: vendored SigmaHQ rules did not all convert: %+v", plat, rep)
		}
		shipped, _ := filepath.Glob("../../rules/sigma/" + plat + "/*.yml")
		if len(shipped) == 0 || len(shipped) != rep.Summary.Converted {
			t.Fatalf("%s: %d shipped rules, %d converted", plat, len(shipped), rep.Summary.Converted)
		}
		for _, f := range shipped {
			want, err := os.ReadFile(filepath.Join(out, filepath.Base(f)))
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(f); string(got) != string(want) {
				t.Errorf("%s differs from the converter output; re-run: zaafvesper sigma convert pkg/sigma/testdata/sigmahq-%s -o rules/sigma/%s --force", f, plat, plat)
			}
		}
	}
}

func TestShippedSigmaWindowsLinuxLoad(t *testing.T) {
	rs, err := rules.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, r := range rs.Rules {
		f := filepath.ToSlash(r.File)
		for _, plat := range []string{"windows", "linux"} {
			if !strings.Contains(f, "/sigma/"+plat+"/") {
				continue
			}
			n[plat]++
			if r.Labels["sigma.author"] == "" || len(r.References) == 0 || r.Labels["sigma.id"] == "" {
				t.Errorf("%s: DRL 1.1 attribution missing (author, references, id)", r.File)
			}
			if len(r.Platforms) != 1 || r.Platforms[0] != plat {
				t.Errorf("%s: platforms %v", r.File, r.Platforms)
			}
			if !strings.Contains(r.Output, "Sigma rule by") {
				t.Errorf("%s: alert text must carry the Sigma author", r.File)
			}
		}
	}
	if n["windows"] < 10 || n["linux"] < 10 {
		t.Fatalf("loaded %v converted rules", n)
	}
}
