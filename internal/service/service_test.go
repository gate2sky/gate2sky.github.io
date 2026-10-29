package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gate2net/gate2net.github.io/internal/config"
)

func TestUnit(t *testing.T) {
	opts := Options{ConfigPath: "/etc/gate2net/gate2net.yaml", Config: &config.Config{DataDir: "/var/lib/gate2net"}}
	unit, err := Unit(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/gate2net start --config /etc/gate2net/gate2net.yaml",
		"User=gate2net",
		"ReadWritePaths=/var/lib/gate2net",
		"EnvironmentFile=-/etc/gate2net/gate2net.env",
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
	opts := Options{ConfigPath: "/etc/gate2net/gate2net.yaml", Config: &config.Config{DataDir: "/var/lib/gate2net"}, DryRun: true, Out: &out}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"would: write /etc/systemd/system/gate2net.service", "would: enable and start gate2net", "[Service]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
}
