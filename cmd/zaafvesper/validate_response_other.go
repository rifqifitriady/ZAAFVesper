//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"os"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

func sysExec(string, []string) error                { return errors.New("not supported") }
func exeSuffix() string                             { return "" }
func validateTempRoot() string                      { return os.TempDir() }
func waitState(int32, bool, time.Duration) bool     { return false }
func (h *vHarness) platformConfig(*response.Config) {}
func (h *vHarness) runPlatform()                    {}
