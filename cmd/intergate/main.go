// Command intergate exposes local HTTP services on subdomains through SSH
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
	"strings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `intergate exposes local services on your domain through SSH tunnels.

Usage:
  intergate start [--detached]     run the server (in the background with --detached)
  intergate stop                   stop a server started with --detached
  intergate status                 show whether the server is running
  intergate config                 set up intergate or manage subdomains, SSH keys
                                   and users in an interactive wizard
  intergate setup-url              print a new one-time link to the dashboard's
                                   setup (email delivery and the owner)
  intergate service --install      install and start intergate as a systemd service
  intergate service --uninstall    stop and remove the systemd service
  intergate service --status       show the systemd service status
  intergate tunnel SUBDOMAIN ...   forward a subdomain's HTTP tunnel and TCP or
                                   UDP ports from this machine (see --help)
  intergate version                print the version

Every server command accepts --config FILE. Without it, intergate uses
$INTERGATE_CONFIG, ./intergate.yaml or /etc/intergate/intergate.yaml,
whichever exists first.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if !errors.Is(err, errQuiet) {
			fmt.Fprintln(os.Stderr, "intergate:", err)
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
	case "setup-url":
		return cmdSetupURL(args, out)
	case "service":
		return cmdService(args, out)
	case "tunnel":
		return cmdTunnel(args)
	case "version", "--version", "-version":
		fmt.Fprintln(out, "intergate", version)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Fprint(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// newFlags returns a flag set with the --config flag every command takes.
func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("intergate "+name, flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	return fs, path
}

const systemConfigPath = "/etc/intergate/intergate.yaml"

// configPath resolves the configuration file to use.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	env := os.Getenv("INTERGATE_CONFIG")
	if env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if env == "" {
		for _, p := range []string{"intergate.yaml", systemConfigPath} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// intergate was called gate2net, and gate2sky before: their
	// configuration still works.
	if p := legacyConfigPath(env); p != "" {
		return p
	}
	if env != "" {
		return env
	}
	// Nothing yet: `intergate config` creates it here.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return systemConfigPath
	}
	return "intergate.yaml"
}

// legacyConfigPath finds the configuration of gate2net or gate2sky,
// intergate's former names, when there is none under the new one: for
// gate2net, $GATE2NET_CONFIG, a gate2net.yaml next to $INTERGATE_CONFIG (a
// Docker volume made before the rename), ./gate2net.yaml or
// /etc/gate2net/gate2net.yaml; then the same for gate2sky.
func legacyConfigPath(env string) string {
	var candidates []string
	for _, name := range []string{"gate2net", "gate2sky"} {
		candidates = append(candidates, os.Getenv(strings.ToUpper(name)+"_CONFIG"))
		if env != "" {
			candidates = append(candidates, filepath.Join(filepath.Dir(env), name+".yaml"))
		} else {
			candidates = append(candidates, name+".yaml", "/etc/"+name+"/"+name+".yaml")
		}
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
