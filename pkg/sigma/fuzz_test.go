package sigma

import (
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

// FuzzConvert feeds arbitrary bytes through Parse and Convert: neither may
// panic, and every converted rule must load in the rule engine.
func FuzzConvert(f *testing.F) {
	f.Add([]byte(baseRule))
	f.Add([]byte("title: t\nlogsource: {product: linux, category: network_connection}\ndetection:\n  s: {DestinationIp|cidr: [10.0.0.0/8], Initiated: 'true'}\n  k: [a, 'b*c\\\\*']\n  condition: 1 of them and not k\n"))
	f.Add([]byte("title: t\nlogsource: {product: windows, category: process_creation}\ndetection:\n  s: {CommandLine|windash|contains|all: [' -a', ' /b'], Image|re|i: '\\\\x$'}\n  condition: s\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			return
		}
		res, err := Convert(r, Options{})
		if err != nil {
			if AsSkip(err) == nil {
				t.Fatal("nil skip for an error")
			}
			return
		}
		if err := Check(res.YAML); err != nil {
			t.Fatalf("converted rule does not load: %v", err)
		}
		if _, err := ql.Compile(res.Condition, nil); err != nil {
			t.Fatalf("condition does not compile: %v", err)
		}
	})
}
