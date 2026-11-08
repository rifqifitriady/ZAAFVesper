//go:build !darwin

package ps

import "errors"

var errUnsupported = errors.New("ps: kernel process identifiers are only read on macOS")

// ReadUniqueID is only implemented on macOS.
func ReadUniqueID(pid int32) (uint64, error) { return 0, errUnsupported }

func readUniqueIdentifiers(pid int32) (uint64, uint32, error) { return 0, 0, errUnsupported }

func readPlatform(pid int32) (bool, error) { return false, errUnsupported }
