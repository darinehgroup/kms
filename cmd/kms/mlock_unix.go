//go:build linux || darwin

package main

import "golang.org/x/sys/unix"

// lockMemory pins the whole process address space so key material cannot be
// swapped to disk (design.md §7/§11). Requires an adequate RLIMIT_MEMLOCK
// (see deploy/kms.service: LimitMEMLOCK=infinity).
func lockMemory() error {
	return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}
