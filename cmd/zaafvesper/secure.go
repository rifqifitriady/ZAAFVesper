package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/yara"
)

const installHint = "install with 'sudo make install' (binary in /usr/local/sbin, rules and config in /usr/local/etc/zaafvesper)"

// checkExecutable refuses to run as root from a binary that a non-root user
// could replace: the resolved executable and every directory up to / must
// be root-owned and not group/world writable.
var checkExecutable = checkExecutableFile

func checkExecutableFile() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	if err := config.CheckOwnership(real); err != nil {
		return fmt.Errorf("the zaafvesper binary %s is not safe to run as root; %s:\n%w", real, installHint, err)
	}
	return nil
}

// checkConfigLocation checks the config file, its directory chain and
// config.d before any of them is parsed.
func checkConfigLocation(path string, explicit bool) error {
	if path == "" {
		return nil
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && !explicit {
		return nil
	}
	paths := []string{path}
	if d := filepath.Join(filepath.Dir(path), "config.d"); exists(d) {
		paths = append(paths, d)
	}
	if err := config.CheckOwnership(paths...); err != nil {
		return fmt.Errorf("configuration is not safe to use as root; %s:\n%w", installHint, err)
	}
	return nil
}

// checkRulesLocation checks the rules tree (macros, testdata, yara inside it)
// and a separate YARA directory, before any rule is parsed.
func checkRulesLocation(rulesDir, yaraDir string) error {
	paths := []string{rulesDir}
	if yaraDir != "" && exists(yaraDir) && !isWithin(yaraDir, rulesDir) {
		paths = append(paths, yaraDir)
	}
	if err := config.CheckOwnership(paths...); err != nil {
		return fmt.Errorf("rules are not safe to use as root; %s:\n%w", installHint, err)
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// checkYaraImages refuses YARA as root when a loaded dynamic library (for
// example libyara from Homebrew) or a directory on its path could be
// replaced by a non-root user. Without the yara build tag it returns nil.
var checkYaraImages = yara.CheckLoadedImages
