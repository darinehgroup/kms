//go:build !linux && !darwin

package main

import "errors"

func lockMemory() error {
	return errors.New("mlock is not supported on this platform")
}
