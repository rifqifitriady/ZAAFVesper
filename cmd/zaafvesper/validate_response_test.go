package main

import (
	"strings"
	"testing"
)

// TestValidateResponseGuard: the live harness refuses to run unless the
// throw-away-runner guard is set, and never appears in the usage text.
func TestValidateResponseGuard(t *testing.T) {
	t.Setenv(validateGuardEnv, "")
	code, _, errs := runCLI(t, "validate-response")
	if code != 2 || !strings.Contains(errs, "throw-away machine") {
		t.Fatalf("code %d: %q", code, errs)
	}
	if strings.Contains(usage, "validate-response") {
		t.Fatal("the harness must not be in the usage text")
	}
}
