//go:build yara && darwin

package yara

/*
#include <mach-o/dyld.h>
*/
import "C"

import (
	"os"
	"path/filepath"
)

// CheckLoadedImages returns an error naming the first image loaded into this
// process (the executable and every dylib, from dyld) outside /usr/lib/ and
// /System/ whose file or any ancestor directory is not owned by root or is
// group/world-writable. A root sensor that loaded such a library (for example
// a dynamically linked Homebrew libyara under a user-owned /opt/homebrew) can
// be hijacked by that user; callers running as root must fail closed on it.
func CheckLoadedImages() error {
	return checkImages(loadedImages(), os.Lstat, filepath.EvalSymlinks)
}

func loadedImages() []string {
	n := uint32(C._dyld_image_count())
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		if name := C._dyld_get_image_name(C.uint32_t(i)); name != nil {
			out = append(out, C.GoString(name))
		}
	}
	return out
}
