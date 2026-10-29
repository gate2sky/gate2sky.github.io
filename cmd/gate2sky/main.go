// Command gate2sky exposes local HTTP services on subdomains through SSH
// remote forwarding, managed from a web dashboard.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `gate2sky exposes local services on your domain through SSH tunnels.

Usage:
  gate2sky start [--detached]     run the server (in the background with --detached)
  gate2sky stop                   stop a server started with --detached
  gate2sky status                 show whether the server is running
  gate2sky config                 set up gate2sky or manage subdomains, SSH keys
                                    and users in an interactive wizard
  gate2sky service --install      install and start gate2sky as a systemd service
  gate2sky service --uninstall    stop and remove the systemd service
  gate2sky service --status       show the systemd service status
  gate2sky tunnel SUBDOMAIN ...    forward a subdomain's HTTP tunnel and TCP or
                                    UDP ports from this machine (see --help)
  gate2sky version                print the version

Every server command accepts --config FILE. Without it, gate2sky uses
$GATE2SKY_CONFIG, ./gate2sky.yaml or /etc/gate2sky/gate2sky.yaml,
whichever exists first.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if !errors.Is(err, errQuiet) {
			fmt.Fprintln(os.Stderr, "gate2sky:", err)
		}
		os.Exit(1)
	}
}

// errQuiet signals a failure that was already reported.
var errQuiet = errors.New("failed")

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "start":
		return cmdStart(args)
	case "stop":
		return cmdStop(args, out)
	case "status":
		return cmdStatus(args, out)
	case "config":
		return cmdConfig(args)
	case "service":
		return cmdService(args, out)
	case "tunnel":
		return cmdTunnel(args)
	case "version", "--version", "-version":
		fmt.Fprintln(out, "gate2sky", version)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Fprint(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// newFlags returns a flag set with the --config flag every command takes.
func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("gate2sky "+name, flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	return fs, path
}

const systemConfigPath = "/etc/gate2sky/gate2sky.yaml"

// configPath resolves the configuration file to use.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := os.Getenv("GATE2SKY_CONFIG"); p != "" {
		return p
	}
	for _, p := range []string{"gate2sky.yaml", systemConfigPath} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Nothing yet: `gate2sky config` creates it here.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return systemConfigPath
	}
	return "gate2sky.yaml"
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
