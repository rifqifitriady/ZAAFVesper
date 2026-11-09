//go:build unix

package nofollow

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Open opens path read-only with O_NOFOLLOW (and O_NONBLOCK, so a FIFO
// planted at the path cannot block the caller).
func Open(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: %w", path, ErrLink)
		}
		return nil, err
	}
	return f, nil
}
