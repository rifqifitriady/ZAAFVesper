//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// protectedDirSDDL is the DACL given to an output directory ZAAFVesper
// creates while elevated: SYSTEM and Administrators only, inheritance from
// the parent (ProgramData lets Users add files) cut off.
const protectedDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// openOutputDir creates dir when it is missing (elevated: with a
// SYSTEM/Administrators-only DACL), refuses a reparse point, and, elevated,
// checks the directory and its ancestors with config.CheckOwnership. Windows
// has no directory descriptors to work relative to: every later operation
// names a file directly in this directory and never follows a reparse point
// (CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, Lstat).
func openOutputDir(dir string, asRoot bool) (*outputDir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := mkdirOutput(abs, asRoot); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("output directory: %w", err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("output directory %s: %w", abs, err)
	}
	if !fi.IsDir() || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || reparse(fi) {
		return nil, fmt.Errorf("output directory %s: not a plain directory (links and junctions are refused)", abs)
	}
	if asRoot {
		if err := config.CheckOwnership(abs); err != nil {
			return nil, fmt.Errorf("output directory %s is not safe to write as an administrator:\n%w", abs, err)
		}
	}
	return &outputDir{path: abs, fd: -1, now: time.Now}, nil
}

func mkdirOutput(abs string, protected bool) error {
	if !protected {
		return os.Mkdir(abs, 0o700)
	}
	sd, err := windows.SecurityDescriptorFromString(protectedDirSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fs.ErrExist
		}
		return err
	}
	return nil
}

func reparse(fi fs.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// createExcl creates name with CREATE_NEW (fails on any existing name, a
// link included); an existing name gives an error matching fs.ErrExist.
func (d *outputDir) createExcl(name string) (*os.File, error) {
	full := filepath.Join(d.path, name)
	p, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, fs.ErrExist
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), full), nil
}

func (d *outputDir) names() ([]string, error) {
	ents, err := os.ReadDir(d.path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}

func (d *outputDir) regularSize(name string) (int64, bool) {
	fi, err := os.Lstat(filepath.Join(d.path, name))
	if err != nil || !fi.Mode().IsRegular() || reparse(fi) {
		return 0, false
	}
	return fi.Size(), true
}

func (d *outputDir) unlink(name string) error { return os.Remove(filepath.Join(d.path, name)) }

func (d *outputDir) close() error { return nil }
