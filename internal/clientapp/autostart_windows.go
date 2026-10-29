package clientapp

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// The app starts with Windows from the user's Run key, minimized to the
// tray.
const (
	runKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue = "gate2net"
)

// AutostartSupported reports whether SetAutostart can work here.
func AutostartSupported() bool { return true }

// AutostartEnabled reports whether the app starts with the system.
func AutostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

// SetAutostart makes this executable start with the system, or not.
func SetAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runValue, `"`+exe+`" --background`)
}
