package client

import (
	"io"
	"os"
)

// agentConn connects to the OpenSSH agent of Windows (the "OpenSSH
// Authentication Agent" service), or to the named pipe SSH_AUTH_SOCK names.
// A named pipe opens like a file.
func agentConn() (io.ReadWriteCloser, error) {
	pipe := os.Getenv("SSH_AUTH_SOCK")
	if pipe == "" {
		pipe = `\\.\pipe\openssh-ssh-agent`
	}
	return os.OpenFile(pipe, os.O_RDWR, 0)
}
