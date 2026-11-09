//go:build windows

package main

// oNoFollow: Windows has no O_NOFOLLOW. sigma convert writes through os.Root,
// which keeps every open inside the output folder, creates with O_EXCL (an
// existing name, link included, is never opened) and checks with Lstat that
// a file it replaces is a regular file.
const oNoFollow = 0
