// Package service installs gate2net as a systemd service.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/gate2net/gate2net.github.io/internal/config"
)

const (
	name       = "gate2net"
	unitPath   = "/etc/systemd/system/gate2net.service"
	binaryPath = "/usr/local/bin/gate2net"
	userName   = "gate2net"
)

// Options configure Install and Uninstall.
type Options struct {
	// ConfigPath is the absolute path of the configuration file.
	ConfigPath string
	Config     *config.Config
	// DryRun prints the steps without running them.
	DryRun bool
	Out    io.Writer
}

var unitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=gate2net SSH tunnel server
Documentation=https://github.com/gate2net/gate2net.github.io
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.User}}
WorkingDirectory={{.WorkDir}}
ExecStart={{.Binary}} start --config {{.Config}}
# Optional KEY=value file, read by systemd as root, for secrets referenced
# as ${KEY} in the configuration.
EnvironmentFile=-{{.EnvFile}}
Restart=on-failure
RestartSec=2s

# Bind ports below 1024 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={{.DataDir}}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077

[Install]
WantedBy=multi-user.target
`))

// Unit renders the systemd unit for opts.
func Unit(opts Options) (string, error) {
	var b bytes.Buffer
	err := unitTemplate.Execute(&b, map[string]string{
		"User":    userName,
		"WorkDir": filepath.Dir(opts.ConfigPath),
		"Binary":  binaryPath,
		"Config":  opts.ConfigPath,
		"EnvFile": strings.TrimSuffix(opts.ConfigPath, filepath.Ext(opts.ConfigPath)) + ".env",
		"DataDir": dataDir(opts),
	})
	return b.String(), err
}

// dataDir is the absolute data directory (config.Load resolves relative
// paths against the configuration file's directory).
func dataDir(opts Options) string {
	if d, err := filepath.Abs(opts.Config.DataDir); err == nil {
		return d
	}
	return opts.Config.DataDir
}

func supported() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("service installation supports systemd on Linux only; on %s run `gate2net start --detached`", runtime.GOOS)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running on this machine; run `gate2net start --detached` instead")
	}
	return nil
}

// Active reports whether the systemd service is running.
func Active() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat(unitPath); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

type step struct {
	desc string
	run  func() error
}

func execute(opts Options, steps []step) error {
	for _, s := range steps {
		if opts.DryRun {
			fmt.Fprintln(opts.Out, "would:", s.desc)
			continue
		}
		fmt.Fprintln(opts.Out, "→", s.desc)
		if err := s.run(); err != nil {
			return fmt.Errorf("%s: %w", s.desc, err)
		}
	}
	return nil
}

func command(name string, args ...string) func() error {
	return func() error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// Install sets up and starts the service: binary in /usr/local/bin, a
// dedicated system user owning the data directory, and a hardened unit.
func Install(opts Options) error {
	if !opts.DryRun {
		if err := supported(); err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			return errors.New("installing the service needs root: run it with sudo")
		}
	}
	unit, err := Unit(opts)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	data := dataDir(opts)

	var steps []step
	if exe != binaryPath {
		steps = append(steps, step{"copy " + exe + " to " + binaryPath, func() error { return copyBinary(exe, binaryPath) }})
	}
	if _, err := user.Lookup(userName); err != nil {
		steps = append(steps, step{"create system user " + userName, createUser(data)})
	}
	steps = append(steps,
		step{"give " + userName + " the data directory " + data, func() error { return ownDataDir(data) }},
		step{"let " + userName + " read " + opts.ConfigPath + " (mode 0640)", func() error { return shareConfig(opts.ConfigPath) }},
		step{"write " + unitPath, func() error { return os.WriteFile(unitPath, []byte(unit), 0o644) }},
		step{"reload systemd", command("systemctl", "daemon-reload")},
		step{"enable and start " + name, command("systemctl", "enable", "--now", name)},
	)
	if opts.DryRun {
		fmt.Fprintf(opts.Out, "Unit file %s:\n\n%s\n", unitPath, unit)
	}
	if err := execute(opts, steps); err != nil {
		return err
	}
	if !opts.DryRun {
		fmt.Fprintf(opts.Out, "\ngate2net is running as a service.\n"+
			"  status:  systemctl status gate2net\n"+
			"  logs:    journalctl -u gate2net -f\n"+
			"  manage:  sudo gate2net config\n")
	}
	return nil
}

// Uninstall stops and removes the service, keeping configuration and data.
func Uninstall(opts Options) error {
	if !opts.DryRun {
		if err := supported(); err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			return errors.New("removing the service needs root: run it with sudo")
		}
		if _, err := os.Stat(unitPath); err != nil {
			return errors.New("the gate2net service is not installed")
		}
	}
	err := execute(opts, []step{
		{"stop and disable " + name, command("systemctl", "disable", "--now", name)},
		{"remove " + unitPath, func() error { return os.Remove(unitPath) }},
		{"reload systemd", command("systemctl", "daemon-reload")},
	})
	if err == nil && !opts.DryRun {
		fmt.Fprintln(opts.Out, "\nThe service was removed. The configuration, data directory, binary and user were kept.")
	}
	return err
}

// Status shows `systemctl status gate2net`.
func Status(out io.Writer) error {
	if err := supported(); err != nil {
		return err
	}
	cmd := exec.Command("systemctl", "status", "--no-pager", name)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil // systemctl reports inactive services with a non-zero code
		}
		return err
	}
	return nil
}

func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func createUser(home string) func() error {
	return func() error {
		if path, err := exec.LookPath("useradd"); err == nil {
			return command(path, "--system", "--user-group", "--home-dir", home, "--no-create-home",
				"--shell", "/usr/sbin/nologin", "--comment", "gate2net", userName)()
		}
		if path, err := exec.LookPath("adduser"); err == nil { // BusyBox (Alpine)
			if err := command("addgroup", "-S", userName)(); err != nil {
				return err
			}
			return command(path, "-S", "-D", "-H", "-h", home, "-s", "/sbin/nologin", "-G", userName, userName)()
		}
		return errors.New("neither useradd nor adduser is available to create the user")
	}
}

func lookupIDs() (int, int, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// ownDataDir creates the data directory and hands it, and anything a
// previous root-run instance left in it, to the service user.
func ownDataDir(dir string) error {
	uid, gid, err := lookupIDs()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

// shareConfig makes the configuration (which may hold secrets) readable by
// root and the service user only.
func shareConfig(path string) error {
	_, gid, err := lookupIDs()
	if err != nil {
		return err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0o640)
}
