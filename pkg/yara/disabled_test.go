//go:build !yara

package yara

import (
	"errors"
	"testing"
)

func TestDisabledBuild(t *testing.T) {
	s, err := New(Config{RulesDir: "/nonexistent"})
	if s != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("got %v, %v", s, err)
	}
}
