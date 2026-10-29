package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathFindsFormerNames(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, env := range []string{"INTERGATE_CONFIG", "GATE2NET_CONFIG", "GATE2SKY_CONFIG"} {
		t.Setenv(env, "")
	}

	// Docker: $INTERGATE_CONFIG names a file the volume doesn't have yet.
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	os.WriteFile(filepath.Join(data, "gate2sky.yaml"), nil, 0o600)
	t.Setenv("INTERGATE_CONFIG", filepath.Join(data, "intergate.yaml"))
	if got := configPath(""); got != filepath.Join(data, "gate2sky.yaml") {
		t.Errorf("gate2sky's next to INTERGATE_CONFIG: %s", got)
	}
	os.WriteFile(filepath.Join(data, "gate2net.yaml"), nil, 0o600)
	if got := configPath(""); got != filepath.Join(data, "gate2net.yaml") {
		t.Errorf("gate2net's next to INTERGATE_CONFIG: %s", got)
	}
	os.WriteFile(filepath.Join(data, "intergate.yaml"), nil, 0o600)
	if got := configPath(""); got != filepath.Join(data, "intergate.yaml") {
		t.Errorf("INTERGATE_CONFIG once it exists: %s", got)
	}

	t.Setenv("INTERGATE_CONFIG", "")
	os.WriteFile("gate2sky.yaml", nil, 0o600)
	if got := configPath(""); got != "gate2sky.yaml" {
		t.Errorf("./gate2sky.yaml: %s", got)
	}
	t.Setenv("GATE2NET_CONFIG", filepath.Join(data, "gate2net.yaml"))
	if got := configPath(""); got != filepath.Join(data, "gate2net.yaml") {
		t.Errorf("GATE2NET_CONFIG: %s", got)
	}
	t.Setenv("GATE2NET_CONFIG", "")
	os.WriteFile("gate2net.yaml", nil, 0o600)
	if got := configPath(""); got != "gate2net.yaml" {
		t.Errorf("./gate2net.yaml before ./gate2sky.yaml: %s", got)
	}
	os.WriteFile("intergate.yaml", nil, 0o600)
	if got := configPath(""); got != "intergate.yaml" {
		t.Errorf("./intergate.yaml first: %s", got)
	}
	if got := configPath("x.yaml"); got != "x.yaml" {
		t.Errorf("--config: %s", got)
	}
}
