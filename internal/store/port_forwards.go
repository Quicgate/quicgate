package store

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
)

// PortForward is a pure router (UPnP/IGD) forward that quicgate keeps on the
// gateway: WAN ext_port -> int_ip:int_port. Unlike a Stream, the traffic does
// NOT pass through quicgate; the router hands it straight to the target host,
// preserving the real client IP. Used to consolidate manual FRITZ!Box forwards
// (mail to the NAS, Plex, game servers) under quicgate's management so they
// self-heal after a router reboot.
type PortForward struct {
	ID        int64  `json:"id"`
	ExtPort   int    `json:"extPort"`
	Protocol  string `json:"protocol"` // tcp | udp | both
	IntIP     string `json:"intIp"`
	IntPort   int    `json:"intPort"`
	Label     string `json:"label"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// Validate normalizes and checks a forward; a zero IntPort mirrors ExtPort.
func (p *PortForward) Validate() error {
	if p.ExtPort < 1 || p.ExtPort > 65535 {
		return fmt.Errorf("extPort must be 1-65535")
	}
	if p.IntPort == 0 {
		p.IntPort = p.ExtPort
	}
	if p.IntPort < 1 || p.IntPort > 65535 {
		return fmt.Errorf("intPort must be 1-65535")
	}
	switch p.Protocol {
	case "":
		p.Protocol = "tcp"
	case "tcp", "udp", "both":
	default:
		return fmt.Errorf("protocol must be tcp, udp or both")
	}
	p.IntIP = strings.TrimSpace(p.IntIP)
	if net.ParseIP(p.IntIP) == nil {
		return fmt.Errorf("intIp must be a valid IP address")
	}
	return nil
}

const pfCols = "id, ext_port, protocol, int_ip, int_port, label, enabled, created_at, updated_at"

func scanPortForward(rows *sql.Rows) (PortForward, error) {
	var p PortForward
	var enabled int
	err := rows.Scan(&p.ID, &p.ExtPort, &p.Protocol, &p.IntIP, &p.IntPort, &p.Label, &enabled, &p.CreatedAt, &p.UpdatedAt)
	p.Enabled = enabled != 0
	return p, err
}

func (s *Store) ListPortForwards() ([]PortForward, error) {
	rows, err := s.db.Query("SELECT " + pfCols + " FROM port_forwards ORDER BY ext_port")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortForward
	for rows.Next() {
		p, err := scanPortForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) CreatePortForward(p *PortForward) error {
	if err := p.Validate(); err != nil {
		return err
	}
	p.CreatedAt, p.UpdatedAt = now(), now()
	res, err := s.db.Exec("INSERT INTO port_forwards (ext_port, protocol, int_ip, int_port, label, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
		p.ExtPort, p.Protocol, p.IntIP, p.IntPort, p.Label, b2i(p.Enabled), p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return err
	}
	p.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdatePortForward(p *PortForward) error {
	if err := p.Validate(); err != nil {
		return err
	}
	p.UpdatedAt = now()
	res, err := s.db.Exec("UPDATE port_forwards SET ext_port=?, protocol=?, int_ip=?, int_port=?, label=?, enabled=?, updated_at=? WHERE id=?",
		p.ExtPort, p.Protocol, p.IntIP, p.IntPort, p.Label, b2i(p.Enabled), p.UpdatedAt, p.ID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeletePortForward(id int64) error {
	res, err := s.db.Exec("DELETE FROM port_forwards WHERE id=?", id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
