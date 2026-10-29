//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/gate2net/gate2net.github.io/internal/clientapp"
)

// shell opens the window in the browser, without a tray icon, and runs
// until interrupted.
func shell(app *clientapp.App, ui *clientapp.UI, openWindow bool) {
	ui.Show = func() { openBrowser(ui.URL()) }
	fmt.Println("gate2net is running; its window:", ui.URL())
	if openWindow {
		ui.Show()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

func openBrowser(url string) {
	cmd := "xdg-open"
	if runtime.GOOS == "darwin" {
		cmd = "open"
	}
	exec.Command(cmd, url).Start()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gate2net-gui:", err)
	os.Exit(1)
}
