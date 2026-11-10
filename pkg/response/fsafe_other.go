//go:build !darwin && !linux && !windows

package response

import (
	"errors"
	"os"
	"time"
)

// The file actions (quarantine_file, requarantine, remove_persistence) and
// the quarantine vault are implemented on macOS, Linux and Windows only.
// Elsewhere every helper refuses, so the actions are logged as
// refused-unsupported and nothing is touched.

const fileOpsSupported = false

var errUnsupported = errors.New("file response actions are not implemented on this platform")

type fileInfo struct {
	Mode     uint32
	Dev, Ino uint64
	Nlink    uint64
	Size     int64
	UID, GID uint32
	Birth    time.Time
	Attrs    uint32
	Owner    string
}

func (fileInfo) isReg() bool { return false }
func (fileInfo) isDir() bool { return false }

func devKey(d uint64) uint64                              { return d }
func keepXattr(string) bool                               { return false }
func openDirNoFollow(string) (int, error)                 { return -1, errUnsupported }
func openParentNoFollow(string) (int, string, error)      { return -1, "", errUnsupported }
func openAt(int, string) (int, error)                     { return -1, errUnsupported }
func fstatInfo(int) (fileInfo, error)                     { return fileInfo{}, errUnsupported }
func fstatatInfo(int, string) (fileInfo, error)           { return fileInfo{}, errUnsupported }
func fGetPath(int) (string, error)                        { return "", errUnsupported }
func readXattrs(int) (map[string][]byte, []string, error) { return nil, nil, errUnsupported }
func setXattr(int, string, []byte, bool) error            { return errUnsupported }
func hasXattr(int, string) (bool, error)                  { return false, errUnsupported }
func createExcl(int, string, uint32) (*os.File, error)    { return nil, errUnsupported }
func readAllAt(int, string, int64) ([]byte, error)        { return nil, errUnsupported }
func writeAtomicAt(int, string, []byte) error             { return errUnsupported }
func unlinkAt(int, string) error                          { return errUnsupported }
func renameAt(int, string, string) error                  { return errUnsupported }
func mkdirAt(int, string, uint32) error                   { return errUnsupported }
func closeFD(int)                                         {}
func fchmod(int, uint32) error                            { return errUnsupported }
func fchown(int, uint32, uint32) error                    { return errUnsupported }
func flockFD(int) error                                   { return errUnsupported }
func openLockAt(int, string) (int, error)                 { return -1, errUnsupported }
func isNotExist(err error) bool                           { return errors.Is(err, os.ErrNotExist) }
func isExist(err error) bool                              { return errors.Is(err, os.ErrExist) }
func privateDir(int, fileInfo, bool) error                { return errUnsupported }
func sameFileID(fileInfo, uint64, uint64) bool            { return false }
func unlinkBound(int, string, fileInfo) error             { return errUnsupported }

func listDir(string, int) ([]string, error) { return nil, errUnsupported }
func consoleUID() (uint32, error)           { return 0, errUnsupported }
func dirOwner(string) (uint32, error)       { return 0, errUnsupported }

func isLocalFS(int) (bool, error) { return false, errUnsupported }
