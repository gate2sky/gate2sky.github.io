package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gate2sky/gate2sky.github.io/internal/config"
)

func TestUnit(t *testing.T) {
	opts := Options{ConfigPath: "/etc/gate2sky/gate2sky.yaml", Config: &config.Config{DataDir: "/var/lib/gate2sky"}}
	unit, err := Unit(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/gate2sky start --config /etc/gate2sky/gate2sky.yaml",
		"User=gate2sky",
		"ReadWritePaths=/var/lib/gate2sky",
		"EnvironmentFile=-/etc/gate2sky/gate2sky.env",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"ProtectSystem=strict",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want+"\n") {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
}

func TestInstallDryRun(t *testing.T) {
	var out bytes.Buffer
	opts := Options{ConfigPath: "/etc/gate2sky/gate2sky.yaml", Config: &config.Config{DataDir: "/var/lib/gate2sky"}, DryRun: true, Out: &out}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"would: write /etc/systemd/system/gate2sky.service", "would: enable and start gate2sky", "[Service]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
}
