package manage

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/gate2sky/gate2sky.github.io/internal/ports"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
)

// A port's name is a DNS label: clients name it as <port>.<subdomain>.
var portName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

var presetName = regexp.MustCompile(`^[a-z0-9-]{0,32}$`)

// maxAllow bounds the allow list of a port.
const maxAllow = 32

// PortInput describes a port to add or the new settings of one. On an
// update, Protocol and Preset are ignored.
type PortInput struct {
	Name      string
	Protocol  store.Protocol
	Preset    string
	LocalPort int
	// Allow lists addresses and CIDRs; empty lets anyone in.
	Allow []string
}

// check validates in and puts it in canonical form.
func (in *PortInput) check() error {
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if !portName.MatchString(in.Name) {
		return Errorf("a port's name is up to 32 lowercase letters, digits and dashes, like db or minecraft")
	}
	if in.LocalPort < 1 || in.LocalPort > 65535 {
		return Errorf("the local port must be between 1 and 65535")
	}
	if !presetName.MatchString(in.Preset) {
		return Errorf("unknown preset %q", in.Preset)
	}
	if len(in.Allow) > maxAllow {
		return Errorf("a port can allow at most %d addresses or ranges", maxAllow)
	}
	allow, err := ports.ParseAllow(in.Allow)
	if err != nil {
		return Errorf("%v", err)
	}
	in.Allow = ports.FormatAllow(allow)
	return nil
}

// OnlinePorts counts the forwarded ports of d.
func (s *Service) OnlinePorts(d *store.Subdomain) int { return len(s.ports.Subdomain(d.ID)) }

// Ports lists the TCP ports of d.
func (s *Service) Ports(ctx context.Context, d *store.Subdomain) ([]*store.Port, error) {
	return s.store.PortsBySubdomain(ctx, d.ID)
}

// PortStats returns the live forward of a public port, if open.
func (s *Service) PortStats(port int) *ports.Stats {
	if f := s.ports.Get(port); f != nil {
		st := f.Stats()
		return &st
	}
	return nil
}

// CreatePort gives d a TCP port, with a public number of its own from
// tcp.ports.
func (s *Service) CreatePort(ctx context.Context, d *store.Subdomain, in PortInput, actor string) (*store.Port, error) {
	if !s.cfg.TCP.Enabled() {
		return nil, Errorf("this server has no TCP ports (tcp.ports in its configuration)")
	}
	if in.Protocol == "" {
		in.Protocol = store.ProtocolTCP
	}
	switch in.Protocol {
	case store.ProtocolTCP:
	case store.ProtocolUDP:
		return nil, Errorf("UDP ports are not available yet")
	default:
		return nil, Errorf("unknown protocol %q", in.Protocol)
	}
	if err := in.check(); err != nil {
		return nil, err
	}
	existing, err := s.store.PortsBySubdomain(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= s.cfg.TCP.MaxPorts {
		return nil, Errorf("a subdomain can have at most %d TCP ports", s.cfg.TCP.MaxPorts)
	}
	p := &store.Port{
		SubdomainID: d.ID, Subdomain: d.Name, OwnerID: d.UserID,
		Name: in.Name, Protocol: in.Protocol, Allow: in.Allow, Preset: in.Preset, LocalPort: in.LocalPort,
	}
	first, last := s.cfg.TCP.Range()
	switch err := s.store.CreatePort(ctx, p, first, last); {
	case errors.Is(err, store.ErrConflict):
		return nil, Errorf("%s already has a port named %q", d.Name, in.Name)
	case errors.Is(err, store.ErrFull):
		return nil, Errorf("every port of this server is taken; ask an administrator to widen tcp.ports")
	case err != nil:
		return nil, err
	}
	s.log.Info("port created", "subdomain", d.Name, "port", p.Port, "name", p.Name, "by", actor)
	return p, nil
}

// UpdatePort renames a port and changes who may reach it, including on its
// live forward. Connections already in keep going.
func (s *Service) UpdatePort(ctx context.Context, d *store.Subdomain, id int64, in PortInput, actor string) (*store.Port, error) {
	p, err := s.store.PortByID(ctx, d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errorf("that port no longer exists")
	}
	if err != nil {
		return nil, err
	}
	in.Preset = p.Preset
	if err := in.check(); err != nil {
		return nil, err
	}
	p.Name, p.Allow, p.LocalPort = in.Name, in.Allow, in.LocalPort
	switch err := s.store.UpdatePort(ctx, p); {
	case errors.Is(err, store.ErrConflict):
		return nil, Errorf("%s already has a port named %q", d.Name, in.Name)
	case errors.Is(err, store.ErrNotFound):
		return nil, Errorf("that port no longer exists")
	case err != nil:
		return nil, err
	}
	s.ports.Update(p)
	s.log.Info("port updated", "subdomain", d.Name, "port", p.Port, "name", p.Name, "allow", strings.Join(p.Allow, " "), "by", actor)
	return p, nil
}

// DeletePort removes a port and closes its forward. Its number goes back
// to the range.
func (s *Service) DeletePort(ctx context.Context, d *store.Subdomain, id int64, actor string) error {
	err := s.store.DeletePort(ctx, d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("that port no longer exists")
	}
	if err != nil {
		return err
	}
	s.ports.ClosePort(id, "the port was deleted")
	s.log.Info("port deleted", "subdomain", d.Name, "port_id", id, "by", actor)
	return nil
}
