//go:build !darwin

package ps

import (
	"errors"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func listProcesses() ([]event.Proc, error) {
	return nil, errors.New("ps: bootstrap is only implemented on macOS")
}
