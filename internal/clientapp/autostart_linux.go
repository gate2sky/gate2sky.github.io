package clientapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// On Linux the app starts with the desktop session from an XDG autostart
// entry.
func autostartFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autostart", "intergate.desktop"), nil
}

// AutostartSupported reports whether SetAutostart can work here.
func AutostartSupported() bool { return true }

// AutostartEnabled reports whether the app starts with the system.
func AutostartEnabled() bool {
	f, err := autostartFile()
	if err != nil {
		return false
	}
	_, err = os.Stat(f)
	return err == nil
}

// SetAutostart makes this executable start with the system, or not. Either
// way it removes the entry of gate2net, the app's former name.
func SetAutostart(on bool) error {
	f, err := autostartFile()
	if err != nil {
		return err
	}
	os.Remove(filepath.Join(filepath.Dir(f), "gate2net.desktop"))
	if !on {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		return err
	}
	entry := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=intergate\nExec=%q --background\nX-GNOME-Autostart-enabled=true\n", exe)
	return os.WriteFile(f, []byte(entry), 0o644)
}
