package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// AuthMethods offers the keys of ssh-agent (Windows' too), then the given key files, or
// the usual ones in ~/.ssh.
func AuthMethods(files []string) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	if c, err := agentConn(); err == nil {
		if list, err := agent.NewClient(c).Signers(); err == nil {
			signers = append(signers, list...)
		}
	}
	explicit := len(files) > 0
	if !explicit {
		home, _ := os.UserHomeDir()
		for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			files = append(files, filepath.Join(home, ".ssh", n))
		}
	}
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			if explicit {
				return nil, err
			}
			continue
		}
		s, err := ssh.ParsePrivateKey(pem)
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			if explicit {
				return nil, fmt.Errorf("%s has a passphrase: add it to ssh-agent (ssh-add %s) and try again", f, f)
			}
			continue
		case err != nil:
			if explicit {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			continue
		}
		signers = append(signers, s)
	}
	if len(signers) == 0 {
		return nil, errors.New("no SSH key found: start ssh-agent, or pass -i with your key")
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

// HostKeyCheck accepts the server whose key has this fingerprint, or, with
// none, a key ~/.ssh/known_hosts lists for it.
func HostKeyCheck(fingerprint string) (ssh.HostKeyCallback, error) {
	if fingerprint != "" {
		return func(host string, _ net.Addr, key ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(key); got != fingerprint {
				return fmt.Errorf("host key mismatch for %s: it is %s, not %s", host, got, fingerprint)
			}
			return nil
		}, nil
	}
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".ssh", "known_hosts")
	cb, err := knownhosts.New(path)
	if err != nil {
		return func(host string, _ net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("%s is not in %s; pass --host-key %s if that is the server's key (the dashboard shows it)",
				host, path, ssh.FingerprintSHA256(key))
		}, nil
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(host, remote, key)
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			return fmt.Errorf("%s is not in %s; pass --host-key %s if that is the server's key (the dashboard shows it)",
				host, path, ssh.FingerprintSHA256(key))
		}
		return err
	}, nil
}
