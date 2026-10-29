package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathFindsGate2sky(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("GATE2NET_CONFIG", "")
	t.Setenv("GATE2SKY_CONFIG", "")

	// Docker: $GATE2NET_CONFIG names a file the volume doesn't have yet.
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	os.WriteFile(filepath.Join(data, "gate2sky.yaml"), nil, 0o600)
	t.Setenv("GATE2NET_CONFIG", filepath.Join(data, "gate2net.yaml"))
	if got := configPath(""); got != filepath.Join(data, "gate2sky.yaml") {
		t.Errorf("next to GATE2NET_CONFIG: %s", got)
	}
	os.WriteFile(filepath.Join(data, "gate2net.yaml"), nil, 0o600)
	if got := configPath(""); got != filepath.Join(data, "gate2net.yaml") {
		t.Errorf("GATE2NET_CONFIG once it exists: %s", got)
	}

	t.Setenv("GATE2NET_CONFIG", "")
	os.WriteFile("gate2sky.yaml", nil, 0o600)
	if got := configPath(""); got != "gate2sky.yaml" {
		t.Errorf("./gate2sky.yaml: %s", got)
	}
	os.WriteFile("gate2net.yaml", nil, 0o600)
	if got := configPath(""); got != "gate2net.yaml" {
		t.Errorf("./gate2net.yaml first: %s", got)
	}
	if got := configPath("x.yaml"); got != "x.yaml" {
		t.Errorf("--config: %s", got)
	}
}
