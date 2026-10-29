//go:build !windows

package main

import (
	"io"
	"net"
	"os"
)

// agentConn connects to the ssh-agent of SSH_AUTH_SOCK, if any.
func agentConn() (io.ReadWriteCloser, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, os.ErrNotExist
	}
	return net.Dial("unix", sock)
}
