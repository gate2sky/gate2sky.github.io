package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

	auth, err := client.AuthMethods(identities)
	if err != nil {
		return err
	}
	check, err := client.HostKeyCheck(*hostKey)
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
