package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/config"
)

func TestUnit(t *testing.T) {
	opts := Options{ConfigPath: "/etc/intergate/intergate.yaml", Config: &config.Config{DataDir: "/var/lib/intergate"}}
	unit, err := Unit(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/intergate start --config /etc/intergate/intergate.yaml",
		"User=intergate",
		"ReadWritePaths=/var/lib/intergate",
		"EnvironmentFile=-/etc/intergate/intergate.env",
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
	opts := Options{ConfigPath: "/etc/intergate/intergate.yaml", Config: &config.Config{DataDir: "/var/lib/intergate"}, DryRun: true, Out: &out}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"would: write /etc/systemd/system/intergate.service", "would: enable and start intergate", "[Service]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
}
