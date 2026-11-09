//go:build !zaafvesper_validate

package main

import (
	"strings"
	"testing"
)

// TestValidateResponseNotInReleaseBuilds: without the build tag
// zaafvesper_validate (every release and package build) the live
// validation harness does not exist.
func TestValidateResponseNotInReleaseBuilds(t *testing.T) {
	t.Setenv("ZAAFVESPER_VALIDATE_RESPONSE", "throwaway-runner")
	for _, args := range [][]string{{"validate-response"}, {"validate-response", "sleeper", "--for", "0s"}} {
		code, _, errs := runCLI(t, args...)
		if code != 2 || !strings.Contains(errs, "unknown command") {
			t.Fatalf("%v: code %d: %q", args, code, errs)
		}
	}
}
