// Package config loads zaafvesper.yml plus config.d/*.yml (sysmon-modular style),
// compiles global exclusions, and provides the file-safety checks ZAAFVesper
// applies when it runs as root.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxConfigFileSize bounds a configuration file.
const MaxConfigFileSize = 1 << 20

// Eslogger configures the event source.
type Eslogger struct {
	Binary         string   `yaml:"binary"`
	ExcludePaths   []string `yaml:"exclude_paths"`   // file path prefixes dropped at the source
	ExcludeSigning []string `yaml:"exclude_signing"` // signing IDs dropped at the source
}

// Yara configures the YARA scanner (only active in a -tags yara build).
type Yara struct {
	Disabled    bool     `yaml:"disabled"`
	RulesDir    string   `yaml:"rules_dir"` // default <rules_dir>/yara
	Workers     int      `yaml:"workers"`
	MaxFileSize int64    `yaml:"max_file_size"`
	TimeoutSec  int      `yaml:"timeout_sec"`
	WatchDirs   []string `yaml:"watch_dirs"`
}

// Source configures how events are requested from the source.
type Source struct {
	// SubscribeWrite also subscribes to the per-syscall eslogger "write"
	// event. Default false: WriteFile comes from "close" with modified=true,
	// one event per modified file instead of one per write(2). This is a
	// deliberate design choice to avoid write floods.
	SubscribeWrite bool `yaml:"subscribe_write"`
}

// Exclusion drops matching events before the rules see them.
type Exclusion struct {
	Name      string   `yaml:"name"`
	Events    []string `yaml:"events"`
	Condition string   `yaml:"condition"`
}

// Response tunes the response actions. None of these settings turns a
// response on: only --enable-response (or --dry-run-response) does.
type Response struct {
	// IsolationAllow lists addresses and networks (CIDR) that
	// isolate_process never blocks: the management allow-list (DNS
	// resolvers, proxies, MDM, the log collector).
	IsolationAllow []string `yaml:"isolation_allow"`
	// IsolationTTL is how long an isolation lasts (default 1h).
	IsolationTTL time.Duration `yaml:"isolation_ttl"`
	// SuspendFor is how long a suspended process stays stopped unless a
	// kill follows (default 30s, at most 10m).
	SuspendFor time.Duration `yaml:"suspend_for"`
	// QuarantineMaxBytes caps the size of a quarantined file (default 128 MiB).
	QuarantineMaxBytes int64 `yaml:"quarantine_max_bytes"`
}

// Config is the merged configuration. There is deliberately no setting that
// enables the response actions: only the --enable-response flag does that.
type Config struct {
	RulesDir string      `yaml:"rules_dir"`
	Source   Source      `yaml:"source"`
	Eslogger Eslogger    `yaml:"eslogger"`
	Yara     Yara        `yaml:"yara"`
	Exclude  []Exclusion `yaml:"exclude"`
	Response Response    `yaml:"response"`

	// Files lists the files that were read, in merge order.
	Files []string `yaml:"-"`
	// Dirs lists the config directories that were read (dir of the main
	// file and its config.d), for the ownership check.
	Dirs []string `yaml:"-"`
}

func decodeFile(path string) (*Config, error) {
	data, err := SecureRead(path, MaxConfigFileSize)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return c, nil
}

// merge folds o into c: non-empty scalars override, lists append.
func (c *Config) merge(o *Config) {
	if o.RulesDir != "" {
		c.RulesDir = o.RulesDir
	}
	if o.Source.SubscribeWrite {
		c.Source.SubscribeWrite = true
	}
	if o.Eslogger.Binary != "" {
		c.Eslogger.Binary = o.Eslogger.Binary
	}
	c.Eslogger.ExcludePaths = append(c.Eslogger.ExcludePaths, o.Eslogger.ExcludePaths...)
	c.Eslogger.ExcludeSigning = append(c.Eslogger.ExcludeSigning, o.Eslogger.ExcludeSigning...)
	if o.Yara.Disabled {
		c.Yara.Disabled = true
	}
	if o.Yara.RulesDir != "" {
		c.Yara.RulesDir = o.Yara.RulesDir
	}
	if o.Yara.Workers != 0 {
		c.Yara.Workers = o.Yara.Workers
	}
	if o.Yara.MaxFileSize != 0 {
		c.Yara.MaxFileSize = o.Yara.MaxFileSize
	}
	if o.Yara.TimeoutSec != 0 {
		c.Yara.TimeoutSec = o.Yara.TimeoutSec
	}
	c.Yara.WatchDirs = append(c.Yara.WatchDirs, o.Yara.WatchDirs...)
	c.Exclude = append(c.Exclude, o.Exclude...)
	c.Response.IsolationAllow = append(c.Response.IsolationAllow, o.Response.IsolationAllow...)
	if o.Response.IsolationTTL != 0 {
		c.Response.IsolationTTL = o.Response.IsolationTTL
	}
	if o.Response.SuspendFor != 0 {
		c.Response.SuspendFor = o.Response.SuspendFor
	}
	if o.Response.QuarantineMaxBytes != 0 {
		c.Response.QuarantineMaxBytes = o.Response.QuarantineMaxBytes
	}
}

// Load reads path and then every *.yml / *.yaml in the config.d directory
// beside it, in name order. An empty path returns an empty configuration.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path == "" {
		return c, nil
	}
	main, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	c.merge(main)
	c.Files = append(c.Files, path)
	dir := filepath.Dir(path)
	c.Dirs = append(c.Dirs, dir)
	dropDir := filepath.Join(dir, "config.d")
	ents, err := os.ReadDir(dropDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, err
	}
	c.Dirs = append(c.Dirs, dropDir)
	var names []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") {
			continue
		}
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		p := filepath.Join(dropDir, n)
		o, err := decodeFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		c.merge(o)
		c.Files = append(c.Files, p)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}
