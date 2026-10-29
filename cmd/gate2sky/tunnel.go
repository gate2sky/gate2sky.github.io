package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/gate2sky/gate2sky.github.io/internal/client"
)

const tunnelUsage = `Usage: gate2sky tunnel [flags] SUBDOMAIN

Forwards a subdomain's HTTP tunnel and ports from this machine, UDP
included, which plain ssh -R can't carry. It reconnects when the
connection drops.

  gate2sky tunnel --server gate.example.com:2222 myapp \
    --http 3000 --tcp db=5432 --udp mc=19132

Flags:
`

// multi is a flag that can be repeated.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdTunnel(args []string) error {
	fs := flag.NewFlagSet("gate2sky tunnel", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), tunnelUsage)
		fs.PrintDefaults()
	}
	server := fs.String("server", os.Getenv("GATE2SKY_SERVER"), "the gate2sky SSH endpoint, HOST[:PORT] (or $GATE2SKY_SERVER)")
	hostKey := fs.String("host-key", os.Getenv("GATE2SKY_HOST_KEY"), "the server's host key fingerprint, SHA256:... (or $GATE2SKY_HOST_KEY); otherwise ~/.ssh/known_hosts")
	var httpPort string
	var tcp, udp, identities multi
	fs.StringVar(&httpPort, "http", "", "forward the HTTP tunnel to this local `PORT` (or HOST:PORT)")
	fs.Var(&tcp, "tcp", "forward the TCP port `NAME=PORT` (repeatable)")
	fs.Var(&udp, "udp", "forward the UDP port `NAME=PORT` (repeatable)")
	fs.Var(&identities, "i", "private key `FILE` (repeatable); by default ssh-agent and ~/.ssh/id_*")

	// The subdomain may come anywhere among the flags, as in the examples.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return errQuiet
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(positional) != 1 {
		fs.Usage()
		return errQuiet
	}
	subdomain := positional[0]
	if *server == "" {
		return errors.New("which server? Pass --server HOST[:PORT] (the dashboard shows it)")
	}
	addr := *server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}

	var forwards []client.Forward
	if httpPort != "" {
		f, err := client.ParseForward(client.HTTP, httpPort)
		if err != nil {
			return err
		}
		forwards = append(forwards, f)
	}
	for kind, list := range map[string]multi{client.TCP: tcp, client.UDP: udp} {
		for _, v := range list {
			f, err := client.ParseForward(kind, v)
			if err != nil {
				return err
			}
			forwards = append(forwards, f)
		}
	}
	if len(forwards) == 0 {
		return errors.New("nothing to forward: add --http, --tcp or --udp")
	}

	auth, err := authMethods(identities)
	if err != nil {
		return err
	}
	check, err := hostKeyCheck(*hostKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, f := range forwards {
		fmt.Printf("gate2sky: %s: %s\n", subdomain, f)
	}
	return client.Run(ctx, client.Options{
		Server:    addr,
		Subdomain: strings.ToLower(subdomain),
		Forwards:  forwards,
		Auth:      auth,
		HostKey:   check,
		Out:       os.Stdout,
	})
}

// authMethods offers the keys of ssh-agent (Windows' too), then the given key files, or
// the usual ones in ~/.ssh.
func authMethods(files []string) ([]ssh.AuthMethod, error) {
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

// hostKeyCheck accepts the server whose key has this fingerprint, or, with
// none, a key ~/.ssh/known_hosts lists for it.
func hostKeyCheck(fingerprint string) (ssh.HostKeyCallback, error) {
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
