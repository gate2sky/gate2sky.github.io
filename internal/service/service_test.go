package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jgermade/securegate/internal/config"
)

func TestUnit(t *testing.T) {
	opts := Options{ConfigPath: "/etc/securegate/securegate.yaml", Config: &config.Config{DataDir: "/var/lib/securegate"}}
	unit, err := Unit(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/securegate start --config /etc/securegate/securegate.yaml",
		"User=securegate",
		"ReadWritePaths=/var/lib/securegate",
		"EnvironmentFile=-/etc/securegate/securegate.env",
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
	opts := Options{ConfigPath: "/etc/securegate/securegate.yaml", Config: &config.Config{DataDir: "/var/lib/securegate"}, DryRun: true, Out: &out}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"would: write /etc/systemd/system/securegate.service", "would: enable and start securegate", "[Service]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
}
