//go:build !windows

package response

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// sep is the path separator of the file actions' paths.
const sep = "/"

func checkCleanAbs(p string) error {
	if p == "" || p[0] != '/' || filepath.Clean(p) != p || strings.ContainsRune(p, 0) || !utf8.ValidString(p) {
		return fmt.Errorf("path %q is not absolute and clean", p)
	}
	return nil
}

// pinnedEnv and pinnedDir are the environment and working directory of
// every pinned command.
func pinnedEnv() []string { return []string{} }
func pinnedDir() string   { return "/" }

func hideWindow(*exec.Cmd) {}
