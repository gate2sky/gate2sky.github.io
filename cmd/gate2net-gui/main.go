// Command gate2net-gui is the gate2net app for the desktop: the client of
// `gate2net tunnel` with a window to set it up and watch it, an icon in
// the system tray, and starting with the system. On Windows the window is
// native (WebView2); elsewhere it opens in the browser.
//
//	gate2net-gui                 open the window
//	gate2net-gui --background    start in the tray, as when starting with Windows
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gate2net/gate2net.github.io/internal/clientapp"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	background := flag.Bool("background", false, "start in the tray without opening the window")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println("gate2net-gui", version)
		return
	}
	if err := run(!*background); err != nil {
		fatal(err)
	}
}

func run(openWindow bool) error {
	path, err := clientapp.DefaultPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock := filepath.Join(filepath.Dir(path), "app.instance")
	if clientapp.ShowRunning(lock) {
		return nil
	}
	app, err := clientapp.Open(path)
	if err != nil {
		return err
	}
	ui, ln, err := clientapp.NewUI(app)
	if err != nil {
		return err
	}
	go http.Serve(ln, ui)
	unpublish, err := ui.Publish(lock)
	if err != nil {
		app.Logf("could not record this instance: %v", err)
	}
	defer unpublish()
	app.Logf("gate2net %s", version)

	if app.Settings().ConnectOnStart {
		if err := app.Connect(); err != nil {
			app.Logf("could not connect: %v", err)
		}
	}
	shell(app, ui, openWindow)
	app.Disconnect()
	return nil
}
