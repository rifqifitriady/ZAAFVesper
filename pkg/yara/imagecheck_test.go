//go:build unix

package yara

import (
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestCheckImages(t *testing.T) {
	fsys := map[string]fakeInfo{
		"/":                         {fs.ModeDir | 0o755, 0},
		"/usr":                      {fs.ModeDir | 0o755, 0},
		"/usr/local":                {fs.ModeDir | 0o755, 0},
		"/usr/local/bin":            {fs.ModeDir | 0o755, 0},
		"/usr/local/bin/zaafvesper": {0o755, 0},
		"/usr/local/bin/gw":         {0o775, 0},
		"/opt":                      {fs.ModeDir | 0o755, 0},
		"/opt/homebrew":             {fs.ModeDir | 0o755, 501},
		"/opt/homebrew/lib":         {fs.ModeDir | 0o775, 501},
		"/opt/homebrew/lib/l.d":     {0o444, 501},
		"/usr/local/lib":            {fs.ModeDir | 0o755, 0},
		"/usr/local/lib/link":       {fs.ModeSymlink | 0o755, 0},
		"/usr/local/lib/real":       {0o644, 0},
		"/usr/local/lib/badlnk":     {fs.ModeSymlink | 0o755, 0},
		"/tmp2":                     {fs.ModeDir | 0o1777, 0},
		"/tmp2/x":                   {0o644, 0},
	}
	lstat := func(p string) (fs.FileInfo, error) {
		if fi, ok := fsys[p]; ok {
			return fi, nil
		}
		return nil, fs.ErrNotExist
	}
	resolve := func(p string) (string, error) {
		switch p {
		case "/usr/local/lib/link":
			return "/usr/local/lib/real", nil
		case "/usr/local/lib/badlnk":
			return "/opt/homebrew/lib/l.d", nil
		}
		return p, nil
	}
	cases := []struct {
		images []string
		errHas string // "" = ok
	}{
		{[]string{"/usr/local/bin/zaafvesper", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/X"}, ""},
		{[]string{"/usr/local/bin/zaafvesper", "/opt/homebrew/lib/l.d"}, "/opt/homebrew/lib/l.d"},
		{[]string{"/usr/local/bin/gw"}, "writable"},
		{[]string{"/usr/local/lib/link"}, ""},
		{[]string{"/usr/local/lib/badlnk"}, "-> /opt/homebrew/lib/l.d"},
		{[]string{"/tmp2/x"}, "/tmp2"},
		{[]string{"relative.dylib"}, "relative"},
		{[]string{"/missing/lib"}, "not exist"},
	}
	for _, c := range cases {
		err := checkImages(c.images, lstat, resolve)
		switch {
		case c.errHas == "" && err != nil:
			t.Errorf("%v: unexpected %v", c.images, err)
		case c.errHas != "" && (err == nil || !strings.Contains(err.Error(), c.errHas)):
			t.Errorf("%v: got %v, want error containing %q", c.images, err, c.errHas)
		}
	}
	// The first offending image is named.
	err := checkImages([]string{"/usr/local/bin/gw", "/opt/homebrew/lib/l.d"}, lstat, resolve)
	if err == nil || !strings.Contains(err.Error(), "/usr/local/bin/gw") {
		t.Errorf("first offender: %v", err)
	}
	if !errors.Is(checkImages([]string{"/missing"}, lstat, resolve), fs.ErrNotExist) {
		t.Error("lstat error not wrapped")
	}
}
