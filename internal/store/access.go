package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type storedUser struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
}

// Validate checks an access list; prev (may be nil) supplies existing hashes
// for users whose password was left empty on update.
func (a *AccessList) Validate(prev *AccessList) error {
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" {
		return errors.New("access list name is required")
	}
	if a.Satisfy == "" {
		a.Satisfy = "any"
	}
	if a.Satisfy != "any" && a.Satisfy != "all" {
		return fmt.Errorf("satisfy must be any or all, got %q", a.Satisfy)
	}
	if len(a.Rules) == 0 && len(a.Users) == 0 {
		return errors.New("access list needs at least one rule or one user")
	}
	for i, r := range a.Rules {
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("rule %d: action must be allow or deny", i+1)
		}
		cidr := strings.TrimSpace(r.CIDR)
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("rule %d: invalid CIDR %q", i+1, r.CIDR)
		}
		a.Rules[i].CIDR = cidr
	}
	prevHashes := map[string]string{}
	if prev != nil {
		for _, u := range prev.Users {
			prevHashes[u.Username] = u.Hash
		}
	}
	seen := map[string]bool{}
	for i, u := range a.Users {
		name := strings.TrimSpace(u.Username)
		if name == "" {
			return fmt.Errorf("user %d: username is required", i+1)
		}
		if seen[name] {
			return fmt.Errorf("duplicate username %q", name)
		}
		seen[name] = true
		a.Users[i].Username = name
		switch {
		case u.Password != "":
			hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			a.Users[i].Hash = string(hash)
		case prevHashes[name] != "":
			a.Users[i].Hash = prevHashes[name]
		default:
			return fmt.Errorf("user %q: password is required", name)
		}
		a.Users[i].Password = ""
	}
	return nil
}

func scanAccessList(row interface{ Scan(...any) error }) (AccessList, error) {
	var a AccessList
	var passAuth int
	var rules, users string
	if err := row.Scan(&a.ID, &a.Name, &a.Satisfy, &passAuth, &rules, &users); err != nil {
		return a, err
	}
	a.PassAuth = passAuth == 1
	if err := json.Unmarshal([]byte(rules), &a.Rules); err != nil {
		return a, err
	}
	var su []storedUser
	if err := json.Unmarshal([]byte(users), &su); err != nil {
		return a, err
	}
	for _, u := range su {
		a.Users = append(a.Users, AccessUser{Username: u.Username, Hash: u.Hash})
	}
	return a, nil
}

const accessCols = "id, name, satisfy, pass_auth, rules, users"

func (s *Store) ListAccessLists() ([]AccessList, error) {
	rows, err := s.db.Query("SELECT " + accessCols + " FROM access_lists ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessList
	for rows.Next() {
		a, err := scanAccessList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessList(id int64) (AccessList, error) {
	return scanAccessList(s.db.QueryRow("SELECT "+accessCols+" FROM access_lists WHERE id=?", id))
}

func (a *AccessList) marshalParts() (string, string) {
	rules, _ := json.Marshal(a.Rules)
	su := make([]storedUser, 0, len(a.Users))
	for _, u := range a.Users {
		su = append(su, storedUser{Username: u.Username, Hash: u.Hash})
	}
	users, _ := json.Marshal(su)
	return string(rules), string(users)
}

func (s *Store) CreateAccessList(a *AccessList) error {
	if err := a.Validate(nil); err != nil {
		return err
	}
	rules, users := a.marshalParts()
	res, err := s.db.Exec("INSERT INTO access_lists (name, satisfy, pass_auth, rules, users) VALUES (?,?,?,?,?)",
		a.Name, a.Satisfy, b2i(a.PassAuth), rules, users)
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateAccessList(a *AccessList) error {
	prev, err := s.GetAccessList(a.ID)
	if err != nil {
		return err
	}
	if err := a.Validate(&prev); err != nil {
		return err
	}
	rules, users := a.marshalParts()
	_, err = s.db.Exec("UPDATE access_lists SET name=?, satisfy=?, pass_auth=?, rules=?, users=? WHERE id=?",
		a.Name, a.Satisfy, b2i(a.PassAuth), rules, users, a.ID)
	return err
}

func (s *Store) DeleteAccessList(id int64) error {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE access_list_id=?", id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("access list is used by %d host(s)", n)
	}
	res, err := s.db.Exec("DELETE FROM access_lists WHERE id=?", id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Validate checks a stream; others are the other configured streams (for
// listen-port collision detection) and reserved lists the engine's own ports.
func (st *Stream) Validate(others []Stream, reserved []int) error {
	if st.Protocol == "" {
		st.Protocol = "tcp"
	}
	if st.Protocol != "tcp" && st.Protocol != "udp" && st.Protocol != "both" {
		return fmt.Errorf("protocol must be tcp, udp or both, got %q", st.Protocol)
	}
	if st.ListenPort < 1 || st.ListenPort > 65535 {
		return fmt.Errorf("listen port %d out of range", st.ListenPort)
	}
	for _, p := range reserved {
		if st.ListenPort == p {
			return fmt.Errorf("port %d is reserved by the proxy engine", p)
		}
	}
	if strings.TrimSpace(st.ForwardHost) == "" {
		return errors.New("forward host is required")
	}
	if st.ForwardPort < 1 || st.ForwardPort > 65535 {
		return fmt.Errorf("forward port %d out of range", st.ForwardPort)
	}
	for i, c := range st.AllowedCIDRs {
		cidr := strings.TrimSpace(c)
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("allowed CIDR %d: invalid %q", i+1, c)
		}
		st.AllowedCIDRs[i] = cidr
	}
	overlaps := func(a, b string) bool { return a == "both" || b == "both" || a == b }
	for _, o := range others {
		if o.ID != st.ID && o.ListenPort == st.ListenPort && overlaps(o.Protocol, st.Protocol) {
			return fmt.Errorf("port %d/%s is already used by stream %d", st.ListenPort, st.Protocol, o.ID)
		}
	}
	return nil
}

func scanStream(row interface{ Scan(...any) error }) (Stream, error) {
	var st Stream
	var enabled int
	var cidrs string
	err := row.Scan(&st.ID, &st.ListenPort, &st.Protocol, &st.ForwardHost, &st.ForwardPort, &enabled, &st.CreatedAt, &st.UpdatedAt, &cidrs)
	if err != nil {
		return st, err
	}
	st.Enabled = enabled == 1
	err = json.Unmarshal([]byte(cidrs), &st.AllowedCIDRs)
	return st, err
}

const streamCols = "id, listen_port, protocol, fwd_host, fwd_port, enabled, created_at, updated_at, allowed_cidrs"

func (s *Store) ListStreams() ([]Stream, error) {
	rows, err := s.db.Query("SELECT " + streamCols + " FROM streams ORDER BY listen_port")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stream
	for rows.Next() {
		st, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) CreateStream(st *Stream, reserved []int) error {
	others, err := s.ListStreams()
	if err != nil {
		return err
	}
	if err := st.Validate(others, reserved); err != nil {
		return err
	}
	st.CreatedAt, st.UpdatedAt = now(), now()
	cidrs, _ := json.Marshal(st.AllowedCIDRs)
	res, err := s.db.Exec("INSERT INTO streams (listen_port, protocol, fwd_host, fwd_port, enabled, created_at, updated_at, allowed_cidrs) VALUES (?,?,?,?,?,?,?,?)",
		st.ListenPort, st.Protocol, st.ForwardHost, st.ForwardPort, b2i(st.Enabled), st.CreatedAt, st.UpdatedAt, string(cidrs))
	if err != nil {
		return err
	}
	st.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateStream(st *Stream, reserved []int) error {
	others, err := s.ListStreams()
	if err != nil {
		return err
	}
	if err := st.Validate(others, reserved); err != nil {
		return err
	}
	st.UpdatedAt = now()
	cidrs, _ := json.Marshal(st.AllowedCIDRs)
	res, err := s.db.Exec("UPDATE streams SET listen_port=?, protocol=?, fwd_host=?, fwd_port=?, enabled=?, updated_at=?, allowed_cidrs=? WHERE id=?",
		st.ListenPort, st.Protocol, st.ForwardHost, st.ForwardPort, b2i(st.Enabled), st.UpdatedAt, string(cidrs), st.ID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteStream(id int64) error {
	res, err := s.db.Exec("DELETE FROM streams WHERE id=?", id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
