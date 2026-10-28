//go:build unix

package main

import "syscall"

// detachedProcAttr starts the child in its own session, so it outlives the
// terminal that started it.
func detachedProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
