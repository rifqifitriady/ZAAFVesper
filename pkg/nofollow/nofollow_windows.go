//go:build windows

package nofollow

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Open opens path read-only with FILE_FLAG_OPEN_REPARSE_POINT, so a
// symbolic link, junction or other reparse point in the final component is
// opened itself rather than followed, and is then refused. The file is
// shared for reading only: nobody can write it while it is open.
func Open(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%s: %w", path, ErrLink)
	}
	return os.NewFile(uintptr(h), path), nil
}
