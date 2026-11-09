package sigma

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
	"gopkg.in/yaml.v3"
)

// argMapper maps every Sigma field F to evt.arg[F], so the conformance
// events (flat JSON objects) can be fed to the compiled conditions.
type argMapper struct{ keywords []string }

func (argMapper) Field(f string) (string, bool) {
	if f == "" || strings.ContainsAny(f, "[]\n") {
		return "", false
	}
	return "evt.arg[" + f + "]", true
}
func (argMapper) Value(string, string) (string, string, bool) { return "", "", false }
func (argMapper) HasValues(string) bool                       { return false }
func (m argMapper) KeywordFields() []string                   { return m.keywords }
func (argMapper) Name() string                                { return "conformance test" }

// notSupported lists the vendored rules the converter refuses on purpose,
// with a substring of the reason. Every other rule in a case without
// compile_errors must convert.
var notSupported = map[string]string{
	"c014-v6":     "IPv6 cidr",
	"c028-bare6":  "IPv6 cidr",
	"c028-v6net":  "IPv6 cidr",
	"c026-b64":    "base64offset",
	"c030-ref":    "fieldref",
	"c030-hour":   "hour",
	"c025-ph":     "expand", // invalid in ZAAFElegia; refused here as unsupported
	"c029-1":      "",       // gte|lte: refused (unsupported modifiers)
	"c029-2":      "",       // hour|day: refused (unsupported modifiers)
	"c029-3":      "",
	"c029-4":      "",
	"c029-5":      "",
	"c029-6":      "",
	"c029-7":      "",
	"c029-8":      "",
	"c025-agg":    "",
	"c025-all":    "",
	"c025-cond":   "",
	"c025-mod":    "",
	"c025-null":   "",
	"c025-flagm":  "",
	"c025-flags":  "",
	"c025-flag":   "",
	"placeholder": "",
}

type confCase struct {
	Expected      [][]string `yaml:"expected"`
	CompileErrors int        `yaml:"compile_errors"`
}

// toEvent turns a flat JSON object into an event whose evt.arg holds every
// value as text. It reports false for values ZAAFVesper events cannot hold:
// JSON null (ZAAFVesper has absent, not null), arrays and nested objects.
func toEvent(line []byte) (*event.Event, []string, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, nil, false
	}
	e := &event.Event{Name: event.CreateProcess, Args: map[string]string{}}
	var keys []string
	for k, v := range m {
		switch x := v.(type) {
		case string:
			e.Args[k] = x
		case json.Number:
			e.Args[k] = x.String()
		case bool:
			if x {
				e.Args[k] = "true"
			} else {
				e.Args[k] = "false"
			}
		default:
			return nil, nil, false
		}
		keys = append(keys, k)
	}
	return e, keys, true
}

func TestConformance(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "conformance", "[0-9]*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no conformance cases: %v", err)
	}
	checked, skippedEvents := 0, 0
	for _, dir := range dirs {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, "case.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var cc confCase
			if err := yaml.Unmarshal(raw, &cc); err != nil {
				t.Fatal(err)
			}
			// Events first: keyword searches look in every field the
			// case's events use.
			f, err := os.Open(filepath.Join(dir, "events.ndjson"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var events []*event.Event
			kwSet := map[string]bool{}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := bytes.TrimSpace(sc.Bytes())
				if len(line) == 0 {
					continue
				}
				e, keys, ok := toEvent(line)
				events = append(events, e) // nil = not representable
				if ok {
					for _, k := range keys {
						kwSet[k] = true
					}
				}
			}
			if len(events) != len(cc.Expected) {
				t.Fatalf("%d events, %d expectations", len(events), len(cc.Expected))
			}
			var kw []string
			for k := range kwSet {
				kw = append(kw, "evt.arg["+k+"]")
			}
			sort.Strings(kw)
			mapper := argMapper{keywords: kw}

			ruleFiles, _ := filepath.Glob(filepath.Join(dir, "rules", "*.yml"))
			filters := map[string]*ql.Filter{}
			refused := map[string]bool{}
			for _, rf := range ruleFiles {
				data, err := os.ReadFile(rf)
				if err != nil {
					t.Fatal(err)
				}
				r, err := Parse(data)
				var cond string
				if err == nil {
					cond, err = CompileDetection(r, mapper)
				}
				id := ruleID(data)
				if err != nil {
					refused[id] = true
					want, listed := notSupported[id]
					if !listed {
						t.Errorf("%s (%s) refused but should convert: %v", id, filepath.Base(rf), err)
					} else if want != "" && !strings.Contains(err.Error(), want) {
						t.Errorf("%s refused for %q, want a reason mentioning %q", id, err, want)
					}
					continue
				}
				if _, listed := notSupported[id]; listed {
					t.Errorf("%s converted but is listed as refused: %s", id, cond)
				}
				flt, err := ql.Compile(cond, nil)
				if err != nil {
					t.Fatalf("%s: generated condition does not compile: %v\n%s", id, err, cond)
				}
				filters[id] = flt
			}
			if cc.CompileErrors > 0 && len(refused) != cc.CompileErrors {
				t.Errorf("refused %d rules, case expects %d compile errors", len(refused), cc.CompileErrors)
			}
			for i, e := range events {
				if e == nil {
					skippedEvents++
					continue
				}
				checked++
				var got []string
				for id, flt := range filters {
					if flt.Match(e) {
						got = append(got, id)
					}
				}
				var want []string
				for _, id := range cc.Expected[i] {
					if !refused[id] {
						want = append(want, id)
					}
				}
				sort.Strings(got)
				sort.Strings(want)
				if len(got) == 0 && len(want) == 0 {
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("event %d: matched %v, want %v", i+1, got, want)
				}
			}
		})
	}
	t.Logf("conformance: %d events checked, %d not representable (JSON null, arrays, objects)", checked, skippedEvents)
	if checked < 60 {
		t.Errorf("only %d conformance events checked", checked)
	}
}

func ruleID(data []byte) string {
	var r struct {
		ID string `yaml:"id"`
	}
	_ = yaml.Unmarshal(data, &r)
	return r.ID
}
