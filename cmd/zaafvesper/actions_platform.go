package main

import (
	"io"
	"sort"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// warnUnsupportedActions says at start-up which enabled rules ask for a
// response action this platform does not support; those actions are
// refused (refused-unsupported) when the rule fires, and the alert is
// still raised.
func warnUnsupportedActions(rs *rules.Ruleset, stderr io.Writer) {
	seen := map[string][]string{}
	for _, r := range rs.Enabled() {
		for _, a := range r.Action {
			if why := unsupportedAction(a.Name); why != "" {
				seen[why] = append(seen[why], r.Name)
			}
		}
	}
	whys := make([]string, 0, len(seen))
	for w := range seen {
		whys = append(whys, w)
	}
	sort.Strings(whys)
	for _, w := range whys {
		say(stderr, "warning: %s; it will be refused for %d rule(s): %v", w, len(seen[w]), seen[w])
	}
}
