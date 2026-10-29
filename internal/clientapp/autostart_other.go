//go:build !windows && !linux

package clientapp

import "errors"

// AutostartSupported reports whether SetAutostart can work here.
func AutostartSupported() bool { return false }

// AutostartEnabled reports whether the app starts with the system.
func AutostartEnabled() bool { return false }

// SetAutostart is not available on this system.
func SetAutostart(bool) error { return errors.New("starting with the system is not available here") }
