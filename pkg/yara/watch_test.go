package yara

import "testing"

func TestUnderWatchDir(t *testing.T) {
	globs := []string{"/tmp", "/private/tmp/", "/Users/*/Downloads", "/Users/Shared", "relative/ignored"}
	cases := map[string]bool{
		"/tmp/x":                           true,
		"/private/tmp/a/b/c.sh":            true,
		"/Users/alice/Downloads/evil.dmg":  true,
		"/Users/alice/Downloads/sub/dir/x": true,
		"/Users/Shared/x":                  true,
		"/Users/alice/Downloads":           false, // the directory itself
		"/Users/alice/Documents/x":         false,
		"/Users/alice/bob/Downloads/x":     false, // * does not span /
		"/tmpfoo/x":                        false, // segment match, not string prefix
		"/tmp/../etc/passwd":               false, // unclean paths refused
		"relative/ignored/x":               false,
		"":                                 false,
		"/Users/Sharedx/y":                 false,
	}
	for p, want := range cases {
		if got := UnderWatchDir(p, globs); got != want {
			t.Errorf("%q: got %v want %v", p, got, want)
		}
	}
	if UnderWatchDir("/x/y", []string{"/"}) {
		t.Error("root glob must not watch everything")
	}
	if UnderWatchDir("/a/b", []string{"/[/x"}) {
		t.Error("bad pattern matched")
	}
}

func TestWithDefaults(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.Workers != 2 || c.MaxFileSize != 64<<20 || c.TimeoutSec != 10 || c.QueueSize != 1024 || len(c.WatchDirs) != len(DefaultWatchDirs) {
		t.Errorf("%+v", c)
	}
	c = Config{WatchDirs: []string{}}.WithDefaults()
	if c.WatchDirs == nil || len(c.WatchDirs) != 0 {
		t.Error("explicit empty WatchDirs must stay empty")
	}
}
