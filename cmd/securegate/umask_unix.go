//go:build unix

package main

import "syscall"

// restrictUmask keeps the database, logs and keys private to the service
// user.
func restrictUmask() { syscall.Umask(0o077) }
