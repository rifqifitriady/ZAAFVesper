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

// TestDisabledStub: the stub type exists in builds without yara so callers
// can name *Scanner and its OnDegraded method; everything is inert.
func TestDisabledStub(t *testing.T) {
	var s Scanner
	s.OnDegraded(func(string, string) { t.Fatal("stub reported") })
	s.Submit(nil)
	if err := s.Start(t.Context(), nil); !errors.Is(err, ErrDisabled) || s.Close() != nil || s.Stats() != nil {
		t.Fatal("stub not inert")
	}
}
