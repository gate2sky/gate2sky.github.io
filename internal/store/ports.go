package store

import (
	"context"
	"strings"
	"time"
)

// Protocol is what a port carries.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Port is a public port of a subdomain, forwarded over SSH to a service
// on the client's side. Ports are created from the dashboard, never on
// connect, so their number stays the same and who may reach them is set
// before anyone can.
type Port struct {
	ID          int64
	SubdomainID int64
	Subdomain   string
	OwnerID     int64
	Name        string
	Protocol    Protocol
	Port        int
	// Allow lists the addresses (CIDRs) that may connect; empty lets
	// anyone in.
	Allow []string
	// Preset and LocalPort only serve the dashboard, to label the port
	// and build the command that connects it.
	Preset    string
	LocalPort int
	CreatedAt time.Time
}

const portQuery = `
	SELECT p.id, p.subdomain_id, d.name, d.user_id, p.name, p.protocol, p.port, p.allow, p.preset, p.local_port, p.created_at
	FROM tcp_ports p JOIN subdomains d ON d.id = p.subdomain_id `

func scanPort(row scanner) (*Port, error) {
	var p Port
	var allow string
	var created int64
	if err := row.Scan(&p.ID, &p.SubdomainID, &p.Subdomain, &p.OwnerID, &p.Name, &p.Protocol, &p.Port, &allow, &p.Preset, &p.LocalPort, &created); err != nil {
		return nil, notFound(err)
	}
	p.Allow = strings.Fields(allow)
	p.CreatedAt = fromUnix(created)
	return &p, nil
}

// CreatePort adds p to its subdomain with the lowest free public port
// between first and last, which it sets. It returns ErrConflict if the
// subdomain already has a port with that name, and ErrFull if the range
// has no port left.
func (s *Store) CreatePort(ctx context.Context, p *Port, first, last int) error {
	p.CreatedAt = s.now().Truncate(time.Second)
	if p.Protocol == "" {
		p.Protocol = ProtocolTCP
	}
	// Another port may take the number found between the query and the
	// insert: try the next one.
	for range 10 {
		port, err := s.freePort(ctx, first, last)
		if err != nil {
			return err
		}
		err = s.db.QueryRowContext(ctx, `
			INSERT INTO tcp_ports (subdomain_id, name, protocol, port, allow, preset, local_port, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			p.SubdomainID, p.Name, p.Protocol, port, strings.Join(p.Allow, " "), p.Preset, p.LocalPort, unix(p.CreatedAt)).Scan(&p.ID)
		switch {
		case isUniqueViolation(err) && strings.Contains(err.Error(), "tcp_ports.port"):
			continue
		case isUniqueViolation(err):
			return ErrConflict
		case err != nil:
			return err
		}
		p.Port = port
		return nil
	}
	return ErrFull
}

func (s *Store) freePort(ctx context.Context, first, last int) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT port FROM tcp_ports WHERE port BETWEEN ? AND ? ORDER BY port`, first, last)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	next := first
	for rows.Next() {
		var used int
		if err := rows.Scan(&used); err != nil {
			return 0, err
		}
		if used > next {
			break
		}
		next = used + 1
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if next > last {
		return 0, ErrFull
	}
	return next, nil
}

// PortsBySubdomain lists a subdomain's ports by name.
func (s *Store) PortsBySubdomain(ctx context.Context, subdomainID int64) ([]*Port, error) {
	rows, err := s.db.QueryContext(ctx, portQuery+`WHERE p.subdomain_id = ? ORDER BY p.name`, subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Port
	for rows.Next() {
		p, err := scanPort(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PortByNumber returns the port with this public number.
func (s *Store) PortByNumber(ctx context.Context, port int) (*Port, error) {
	return scanPort(s.db.QueryRowContext(ctx, portQuery+`WHERE p.port = ?`, port))
}

// PortByID returns one of a subdomain's ports.
func (s *Store) PortByID(ctx context.Context, subdomainID, id int64) (*Port, error) {
	return scanPort(s.db.QueryRowContext(ctx, portQuery+`WHERE p.id = ? AND p.subdomain_id = ?`, id, subdomainID))
}

// UpdatePort saves the name, allow list and local port of p. It returns
// ErrConflict if another port of the subdomain has that name.
func (s *Store) UpdatePort(ctx context.Context, p *Port) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tcp_ports SET name = ?, allow = ?, local_port = ? WHERE id = ? AND subdomain_id = ?`,
		p.Name, strings.Join(p.Allow, " "), p.LocalPort, p.ID, p.SubdomainID)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePort removes one of a subdomain's ports. Its number becomes free.
func (s *Store) DeletePort(ctx context.Context, subdomainID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tcp_ports WHERE id = ? AND subdomain_id = ?`, id, subdomainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
