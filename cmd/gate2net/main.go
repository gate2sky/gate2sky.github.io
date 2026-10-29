// Command gate2net exposes local HTTP services on subdomains through SSH
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

const usage = `gate2net exposes local services on your domain through SSH tunnels.

Usage:
  gate2net start [--detached]     run the server (in the background with --detached)
  gate2net stop                   stop a server started with --detached
  gate2net status                 show whether the server is running
  gate2net config                 set up gate2net or manage subdomains, SSH keys
                                    and users in an interactive wizard
  gate2net service --install      install and start gate2net as a systemd service
  gate2net service --uninstall    stop and remove the systemd service
  gate2net service --status       show the systemd service status
  gate2net tunnel SUBDOMAIN ...    forward a subdomain's HTTP tunnel and TCP or
                                    UDP ports from this machine (see --help)
  gate2net version                print the version

Every server command accepts --config FILE. Without it, gate2net uses
$GATE2NET_CONFIG, ./gate2net.yaml or /etc/gate2net/gate2net.yaml,
whichever exists first.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if !errors.Is(err, errQuiet) {
			fmt.Fprintln(os.Stderr, "gate2net:", err)
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
		fmt.Fprintln(out, "gate2net", version)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Fprint(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// newFlags returns a flag set with the --config flag every command takes.
func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("gate2net "+name, flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	return fs, path
}

const systemConfigPath = "/etc/gate2net/gate2net.yaml"

// configPath resolves the configuration file to use.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	env := os.Getenv("GATE2NET_CONFIG")
	if env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if env == "" {
		for _, p := range []string{"gate2net.yaml", systemConfigPath} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// gate2net was called gate2sky: its configuration still works.
	if p := legacyConfigPath(env); p != "" {
		return p
	}
	if env != "" {
		return env
	}
	// Nothing yet: `gate2net config` creates it here.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return systemConfigPath
	}
	return "gate2net.yaml"
}

// legacyConfigPath finds the configuration of gate2sky, gate2net's former
// name, when there is none under the new one: $GATE2SKY_CONFIG, a
// gate2sky.yaml next to $GATE2NET_CONFIG (a Docker volume made before the
// rename), ./gate2sky.yaml or /etc/gate2sky/gate2sky.yaml.
func legacyConfigPath(env string) string {
	candidates := []string{os.Getenv("GATE2SKY_CONFIG")}
	if env != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(env), "gate2sky.yaml"))
	} else {
		candidates = append(candidates, "gate2sky.yaml", "/etc/gate2sky/gate2sky.yaml")
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
