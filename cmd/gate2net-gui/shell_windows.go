package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"

	"github.com/gate2net/gate2net.github.io/internal/clientapp"
)

//go:embed icon.ico
var icon []byte

var (
	user32        = syscall.NewLazyDLL("user32.dll")
	showWindow    = user32.NewProc("ShowWindow")
	setForeground = user32.NewProc("SetForegroundWindow")
	messageBox    = user32.NewProc("MessageBoxW")
	swRestore     = uintptr(9)
	mbIconError   = uintptr(0x10)
)

// window is the app's window, while open.
type window struct {
	mu sync.Mutex
	w  webview2.WebView
}

// open shows the window, creating it on a thread of its own, or brings it
// to the front.
func (win *window) open(url string) {
	win.mu.Lock()
	defer win.mu.Unlock()
	if w := win.w; w != nil {
		w.Dispatch(func() {
			showWindow.Call(uintptr(w.Window()), swRestore)
			setForeground.Call(uintptr(w.Window()))
		})
		return
	}
	ready := make(chan webview2.WebView)
	go func() {
		runtime.LockOSThread()
		data := filepath.Join(os.Getenv("LOCALAPPDATA"), "gate2net", "webview")
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			DataPath:  data,
			WindowOptions: webview2.WindowOptions{
				Title: "gate2net", Width: 840, Height: 780, Center: true,
			},
		})
		ready <- w
		if w == nil {
			// No WebView2 runtime: the browser will do.
			exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
			return
		}
		w.Navigate(url)
		w.Run()
		win.mu.Lock()
		win.w = nil
		win.mu.Unlock()
		w.Destroy()
	}()
	win.w = <-ready
}

// close closes the window, if open.
func (win *window) close() {
	win.mu.Lock()
	w := win.w
	win.mu.Unlock()
	if w != nil {
		w.Dispatch(w.Terminate)
	}
}

func shell(app *clientapp.App, ui *clientapp.UI, openWindow bool) {
	win := &window{}
	ui.Show = func() { win.open(ui.URL()) }
	systray.Run(func() {
		systray.SetIcon(icon)
		systray.SetTooltip("gate2net")
		systray.SetOnTapped(ui.Show)
		open := systray.AddMenuItem("Open gate2net", "Show the window")
		systray.AddSeparator()
		toggle := systray.AddMenuItem("Connect", "")
		dashboard := systray.AddMenuItem("Open the dashboard", "")
		systray.AddSeparator()
		autostart := systray.AddMenuItemCheckbox("Start with Windows", "", clientapp.AutostartEnabled())
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Disconnect and close gate2net")

		update := func() {
			st := app.State()
			running := st.Status == clientapp.Connected || st.Status == clientapp.Connecting || st.Status == clientapp.Waiting
			if running {
				toggle.SetTitle("Disconnect")
			} else {
				toggle.SetTitle("Connect")
			}
			tip := "gate2net: " + string(st.Status)
			if st.Settings.Subdomain != "" {
				tip += " (" + st.Settings.Subdomain + ")"
			}
			systray.SetTooltip(tip)
			if st.Settings.Dashboard == "" {
				dashboard.Disable()
			} else {
				dashboard.Enable()
			}
			if st.Autostart {
				autostart.Check()
			} else {
				autostart.Uncheck()
			}
		}
		update()
		go func() {
			for {
				<-app.Changed()
				update()
			}
		}()
		go func() {
			for {
				select {
				case <-open.ClickedCh:
					ui.Show()
				case <-toggle.ClickedCh:
					if app.Running() {
						app.Disconnect()
					} else if err := app.Connect(); err != nil {
						app.Logf("could not connect: %v", err)
						ui.Show()
					}
				case <-dashboard.ClickedCh:
					if d := app.Settings().Dashboard; d != "" {
						exec.Command("rundll32", "url.dll,FileProtocolHandler", d).Start()
					}
				case <-autostart.ClickedCh:
					if err := clientapp.SetAutostart(!clientapp.AutostartEnabled()); err != nil {
						app.Logf("start with Windows: %v", err)
					}
					update()
				case <-quit.ClickedCh:
					win.close()
					systray.Quit()
					return
				}
			}
		}()
		if openWindow {
			ui.Show()
		}
	}, func() {})
}

func fatal(err error) {
	text, _ := syscall.UTF16PtrFromString(err.Error())
	title, _ := syscall.UTF16PtrFromString("gate2net")
	messageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbIconError)
	os.Exit(1)
}
