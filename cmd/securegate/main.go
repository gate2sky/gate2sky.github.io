// Command securegate exposes local HTTP services on subdomains through SSH
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

const usage = `securegate exposes local services on your domain through SSH tunnels.

Usage:
  securegate start [--detached]     run the server (in the background with --detached)
  securegate stop                   stop a server started with --detached
  securegate status                 show whether the server is running
  securegate config                 set up securegate or manage subdomains, SSH keys
                                    and users in an interactive wizard
  securegate service --install      install and start securegate as a systemd service
  securegate service --uninstall    stop and remove the systemd service
  securegate service --status       show the systemd service status
  securegate version                print the version

Every command accepts --config FILE. Without it, securegate uses
$SECUREGATE_CONFIG, ./securegate.yaml or /etc/securegate/securegate.yaml,
whichever exists first.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if !errors.Is(err, errQuiet) {
			fmt.Fprintln(os.Stderr, "securegate:", err)
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
	case "version", "--version", "-version":
		fmt.Fprintln(out, "securegate", version)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Fprint(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// newFlags returns a flag set with the --config flag every command takes.
func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("securegate "+name, flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	return fs, path
}

const systemConfigPath = "/etc/securegate/securegate.yaml"

// configPath resolves the configuration file to use.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := os.Getenv("SECUREGATE_CONFIG"); p != "" {
		return p
	}
	for _, p := range []string{"securegate.yaml", systemConfigPath} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Nothing yet: `securegate config` creates it here.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return systemConfigPath
	}
	return "securegate.yaml"
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
