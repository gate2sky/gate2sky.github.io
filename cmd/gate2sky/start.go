package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gate2sky/gate2sky.github.io/internal/admin"
	"github.com/gate2sky/gate2sky.github.io/internal/config"
	"github.com/gate2sky/gate2sky.github.io/internal/server"
	"github.com/gate2sky/gate2sky.github.io/internal/service"
)

func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no configuration at %s: create one with `gate2sky config`", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func cmdStart(args []string) error {
	fs, cfgFlag := newFlags("start")
	detached := fs.Bool("detached", false, "run in the background, logging to <data_dir>/gate2sky.log")
	debug := fs.Bool("debug", false, "enable debug logging")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	path := configPath(*cfgFlag)
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	restrictUmask()
	if *detached {
		return startDetached(path, cfg, *debug)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	srv, err := server.New(cfg, log, server.Options{Version: version})
	if err != nil {
		return err
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

// startDetached starts the server in a new session and waits until it
// answers on its admin socket.
func startDetached(path string, cfg *config.Config, debug bool) error {
	if pid := server.RunningPID(cfg); pid != 0 {
		return fmt.Errorf("gate2sky is already running (PID %d)", pid)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(cfg.DataDir, "gate2sky.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"start", "--config", absPath(path)}
	if debug {
		args = append(args, "--debug")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	client := admin.NewClient(cfg.Admin.Socket)
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-exited:
			fmt.Fprintf(os.Stderr, "gate2sky exited during startup. Last lines of %s:\n", logPath)
			printTail(os.Stderr, logPath, 15)
			return errQuiet
		case <-deadline:
			return fmt.Errorf("gate2sky (PID %d) did not become ready in time; see %s", cmd.Process.Pid, logPath)
		case <-time.After(100 * time.Millisecond):
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		st, err := client.Status(ctx)
		cancel()
		if err == nil {
			fmt.Printf("gate2sky %s started in the background (PID %d)\n", st.Version, st.PID)
			fmt.Printf("  dashboard: %s\n  ssh:       %s\n  logs:      %s\n", st.DashboardURL, st.SSH, logPath)
			fmt.Println("Stop it with `gate2sky stop`.")
			return nil
		}
	}
}

func printTail(w io.Writer, path string, n int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	for _, l := range lines {
		fmt.Fprintln(w, "  "+l)
	}
}

func cmdStop(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("stop")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	cfg, err := loadConfig(configPath(*cfgFlag))
	if err != nil {
		return err
	}
	if service.Active() {
		return errors.New("gate2sky runs as a system service; stop it with `sudo systemctl stop gate2sky`")
	}
	pid := server.RunningPID(cfg)
	if pid == 0 {
		fmt.Fprintln(out, "gate2sky is not running")
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("stop PID %d: %w", pid, err)
	}
	for range 100 {
		if server.RunningPID(cfg) == 0 {
			fmt.Fprintf(out, "gate2sky stopped (PID %d)\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("gate2sky (PID %d) did not stop within 10s", pid)
}

func cmdStatus(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("status")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	cfg, err := loadConfig(configPath(*cfgFlag))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := admin.NewClient(cfg.Admin.Socket).Status(ctx)
	if err != nil {
		if pid := server.RunningPID(cfg); pid != 0 {
			return fmt.Errorf("gate2sky is running (PID %d) but its admin socket does not answer: %w", pid, err)
		}
		if errors.Is(err, admin.ErrNotRunning) {
			fmt.Fprintln(out, "gate2sky is not running")
			return errQuiet
		}
		return err
	}
	how := "in the foreground or with --detached"
	if service.Active() {
		how = "as a systemd service"
	}
	fmt.Fprintf(out, "gate2sky %s is running %s (PID %d, up %s)\n", st.Version, how, st.PID, time.Since(st.StartedAt).Round(time.Second))
	fmt.Fprintf(out, "  dashboard:  %s\n  ssh:        %s\n", st.DashboardURL, st.SSH)
	fmt.Fprintf(out, "  subdomains: %d registered, %d online\n  users:      %d\n", st.Subdomains, st.TunnelsOnline, st.Users)
	return nil
}

func cmdService(args []string, out io.Writer) error {
	fs, cfgFlag := newFlags("service")
	install := fs.Bool("install", false, "install and start the systemd service")
	uninstall := fs.Bool("uninstall", false, "stop and remove the systemd service (keeps config and data)")
	status := fs.Bool("status", false, "show the service status")
	dryRun := fs.Bool("dry-run", false, "print what --install or --uninstall would do without doing it")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	opts := service.Options{Out: out, DryRun: *dryRun}
	switch {
	case *install:
		path := configPath(*cfgFlag)
		if *cfgFlag == "" && os.Getenv("GATE2SKY_CONFIG") == "" {
			if _, err := os.Stat(path); err != nil {
				path = systemConfigPath
			}
		}
		opts.ConfigPath = absPath(path)
		if _, err := os.Stat(opts.ConfigPath); err != nil {
			return fmt.Errorf("no configuration at %s: create it first with `sudo gate2sky config --config %s`", opts.ConfigPath, opts.ConfigPath)
		}
		cfg, err := loadConfig(opts.ConfigPath)
		if err != nil {
			return err
		}
		opts.Config = cfg
		return service.Install(opts)
	case *uninstall:
		return service.Uninstall(opts)
	case *status:
		return service.Status(out)
	}
	fs.Usage()
	return errQuiet
}

func cmdConfig(args []string) error {
	fs, cfgFlag := newFlags("config")
	accessible := fs.Bool("accessible", false, "plain prompts instead of the full-screen forms (for screen readers and dumb terminals)")
	if err := fs.Parse(args); err != nil {
		return errQuiet
	}
	path := configPath(*cfgFlag)
	return runWizard(path, *accessible || strings.EqualFold(os.Getenv("ACCESSIBLE"), "1"))
}
