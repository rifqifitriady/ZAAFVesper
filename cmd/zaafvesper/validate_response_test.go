//go:build zaafvesper_validate

package main

import (
	"strings"
	"testing"
)

// TestValidateResponseGuard: the live harness refuses to run unless it is on
// a GitHub-hosted runner with the guard set, also in sleeper mode, and never
// appears in the usage text.
func TestValidateResponseGuard(t *testing.T) {
	for _, env := range []map[string]string{
		{validateGuardEnv: "", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
		{validateGuardEnv: validateGuardValue, "GITHUB_ACTIONS": "", "RUNNER_ENVIRONMENT": "github-hosted"},
		{validateGuardEnv: validateGuardValue, "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
	} {
		for k, v := range env {
			t.Setenv(k, v)
		}
		for _, args := range [][]string{{"validate-response"}, {"validate-response", "sleeper", "--for", "0s"}} {
			code, _, errs := runCLI(t, args...)
			if code != 2 || !strings.Contains(errs, "GitHub-hosted runner") {
				t.Fatalf("%v %v: code %d: %q", env, args, code, errs)
			}
		}
	}
	if strings.Contains(usage, "validate-response") {
		t.Fatal("the harness must not be in the usage text")
	}
}
