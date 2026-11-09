//go:build unix

package main

import "syscall"

// oNoFollow is O_NOFOLLOW where the platform has it (sigma convert's writes).
const oNoFollow = syscall.O_NOFOLLOW
