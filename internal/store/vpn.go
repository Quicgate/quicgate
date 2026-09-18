package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SPEC-wireguard.md parts 2 and 3: devices, who may use them for what, and
// the owners' authorization leases.

// VPNSubject says who a VPN access rule, a LAN policy or the portal's
// enrolment list is about (S53). A group is always named together with the
// identity provider that asserts it: "admins" from one provider is not
// "admins" from another.
type VPNSubject struct {
	Kind     string `json:"kind"`               // any | site | device | peer | user | group | any-user
	Peer     string `json:"peer,omitempty"`     // kind peer: "site:1" or "device:7"
	Provider int64  `json:"provider,omitempty"` // kinds user, group, any-user
	Sub      string `json:"sub,omitempty"`      // kind user
	Group    string `json:"group,omitempty"`    // kind group
}

// Validate checks the shape. identityOnly refuses the kinds that do not name
// a person (policies and enrolment are about people).
func (s *VPNSubject) Validate(identityOnly bool) error {
	s.Peer, s.Sub, s.Group = strings.TrimSpace(s.Peer), strings.TrimSpace(s.Sub), strings.TrimSpace(s.Group)
	switch s.Kind {
	case "any", "site", "device":
		if identityOnly {
			return fmt.Errorf("subject kind %q does not name a person: use group, user or any-user", s.Kind)
		}
		s.Peer, s.Provider, s.Sub, s.Group = "", 0, "", ""
	case "peer":
		if identityOnly {
			return errors.New(`subject kind "peer" does not name a person: use group, user or any-user`)
		}
		kind, id, ok := strings.Cut(s.Peer, ":")
		if _, err := strconv.ParseInt(id, 10, 64); !ok || err != nil || (kind != "site" && kind != "device") {
			return fmt.Errorf("peer %q: want site:<id> or device:<id>", s.Peer)
		}
		s.Provider, s.Sub, s.Group = 0, "", ""
	case "user":
		if s.Provider <= 0 || s.Sub == "" {
			return errors.New("a user subject needs its identity provider and the user's subject id")
		}
		s.Peer, s.Group = "", ""
	case "group":
		if s.Provider <= 0 || s.Group == "" {
			return errors.New("a group subject needs its identity provider and the group's name")
		}
		s.Peer, s.Sub = "", ""
	case "any-user":
		if s.Provider <= 0 {
			return errors.New("an any-user subject needs its identity provider")
		}
		s.Peer, s.Sub, s.Group = "", "", ""
	default:
		return fmt.Errorf("unknown subject kind %q", s.Kind)
	}
	return nil
}

// VPNRoute is one LAN destination a policy grants: an IPv4 prefix in private
// address space, a protocol and ports ("" = all, else "22,80-90").
type VPNRoute struct {
	CIDR  string `json:"cidr"`
	Proto string `json:"proto"` // tcp | udp | any
	Ports string `json:"ports,omitempty"`
}

var privateSpace = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
}

// ParsePorts reads "22,80-90" into inclusive ranges.
func ParsePorts(s string) ([][2]uint16, error) {
	var out [][2]uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil || a == 0 {
			return nil, fmt.Errorf("port %q is not a port", part)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || b < a {
				return nil, fmt.Errorf("port range %q is not a range", part)
			}
		}
		out = append(out, [2]uint16{uint16(a), uint16(b)})
	}
	return out, nil
}

// Validate checks one route (S26): IPv4, private address space only, so the
// forwarder can never be an exit node or an open relay.
func (r *VPNRoute) Validate() error {
	p, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("route %q: want an IPv4 prefix like 192.168.1.0/24", r.CIDR)
	}
	p = p.Masked()
	inside := false
	for _, priv := range privateSpace {
		if priv.Contains(p.Addr()) && p.Bits() >= priv.Bits() {
			inside = true
		}
	}
	if !inside {
		return fmt.Errorf("route %s: only private address space (10/8, 172.16/12, 192.168/16, 100.64/10) can be granted", p)
	}
	r.CIDR = p.String()
	switch r.Proto {
	case "":
		r.Proto = "any"
	case "tcp", "udp", "any":
	default:
		return fmt.Errorf("route %s: protocol must be tcp, udp or any", p)
	}
	if _, err := ParsePorts(r.Ports); err != nil {
		return fmt.Errorf("route %s: %w", p, err)
	}
	r.Ports = strings.ReplaceAll(r.Ports, " ", "")
	return nil
}

// WGDevice is a phone or a laptop. Kind says who issued it: the admin (it
// reaches quicgate's hosts in the tunnel, nothing else), a person through the
// portal (sso: what it may reach follows from the owner's groups and lease),
// or the admin as a break-glass device with its own routes (S33).
type WGDevice struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"` // admin | sso | breakglass
	PublicKey    string     `json:"publicKey"`
	PresharedKey string     `json:"presharedKey,omitempty"` // returned once, on create
	Address      string     `json:"address"`
	Enabled      bool       `json:"enabled"`
	RevokedAt    string     `json:"revokedAt,omitempty"` // terminal; the row stays so the key cannot return (S43)
	Provider     int64      `json:"provider,omitempty"`
	Sub          string     `json:"sub,omitempty"`
	Email        string     `json:"email,omitempty"`
	Routes       []VPNRoute `json:"routes,omitempty"`    // breakglass only
	ExpiresAt    string     `json:"expiresAt,omitempty"` // breakglass
	CreatedAt    string     `json:"createdAt,omitempty"`
}

func wgDevicePSKAAD(id int64) string { return aad("wg_devices", "psk", id) }

// VPNPolicy grants LAN routes to the people a subject names.
type VPNPolicy struct {
	ID      int64      `json:"id"`
	Name    string     `json:"name"`
	Subject VPNSubject `json:"subject"`
	Routes  []VPNRoute `json:"routes"`
}

func (p *VPNPolicy) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errors.New("a policy needs a name")
	}
	if err := p.Subject.Validate(true); err != nil {
		return err
	}
	if len(p.Routes) == 0 {
		return errors.New("a policy needs at least one route")
	}
	for i := range p.Routes {
		if err := p.Routes[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// VPNSession is an owner's authorization lease (S45). The three deadlines are
// absolute and only ever written by a successful renewal (lease, grace) or a
// fresh login (hard).
type VPNSession struct {
	ID           int64     `json:"id"`
	Provider     int64     `json:"provider"`
	Sub          string    `json:"sub"`
	Email        string    `json:"email"`
	Groups       []string  `json:"groups"`
	RefreshToken string    `json:"-"`
	LoginAt      time.Time `json:"loginAt"`
	RenewedAt    time.Time `json:"renewedAt"`
	LeaseUntil   time.Time `json:"leaseUntil"`
	GraceUntil   time.Time `json:"graceUntil"`
	HardUntil    time.Time `json:"hardUntil"`
	// Transient is set while every renewal attempt since the last success
	// failed for a reason that says nothing about the account (network, 5xx).
	// Only then does the grace apply.
	Transient  bool   `json:"transient"`
	State      string `json:"state"` // active | lapsed | ended
	Generation int64  `json:"generation"`
}

// AccessUntil is the moment the owner's devices stop being admitted.
func (s VPNSession) AccessUntil() time.Time {
	until := s.LeaseUntil
	if s.Transient && s.GraceUntil.After(until) {
		until = s.GraceUntil
	}
	if s.HardUntil.Before(until) {
		until = s.HardUntil
	}
	return until
}

// Live reports whether the lease admits the owner's devices now.
func (s VPNSession) Live(now time.Time) bool {
	return s.State == "active" && now.Before(s.AccessUntil())
}

func sessionTokenAAD(id, provider int64, sub string) string {
	// The provider and the subject are part of the place, so a token cannot be
	// opened as another person's or another provider's (S34).
	return aad("vpn_sessions", "refresh_token", fmt.Sprintf("%d/%d/%s", id, provider, sub))
}

func (s *Store) migrateVPN() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS wg_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'admin',
  public_key TEXT UNIQUE NOT NULL,
  psk TEXT NOT NULL DEFAULT '',
  address TEXT UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  revoked_at TEXT NOT NULL DEFAULT '',
  provider INTEGER NOT NULL DEFAULT 0,
  sub TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  routes TEXT NOT NULL DEFAULT '[]',
  expires_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wg_freed (
  address TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS vpn_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL COLLATE NOCASE,
  subject TEXT NOT NULL,
  routes TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS vpn_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider INTEGER NOT NULL,
  sub TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  groups TEXT NOT NULL DEFAULT '[]',
  refresh_token TEXT NOT NULL DEFAULT '',
  login_at TEXT NOT NULL,
  renewed_at TEXT NOT NULL,
  lease_until TEXT NOT NULL,
  grace_until TEXT NOT NULL,
  hard_until TEXT NOT NULL,
  transient INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'active',
  generation INTEGER NOT NULL DEFAULT 1,
  UNIQUE(provider, sub)
);
CREATE TABLE IF NOT EXISTS vpn_blocked (
  provider INTEGER NOT NULL,
  sub TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  blocked_at TEXT NOT NULL,
  PRIMARY KEY (provider, sub)
);`)
	return err
}

// ---- devices ----

const wgDeviceCols = "id, name, kind, public_key, psk, COALESCE(address,''), enabled, revoked_at, provider, sub, email, routes, expires_at, created_at"

func (s *Store) scanWGDevice(row interface{ Scan(...any) error }) (WGDevice, error) {
	var d WGDevice
	var psk, routes string
	var enabled int
	if err := row.Scan(&d.ID, &d.Name, &d.Kind, &d.PublicKey, &psk, &d.Address, &enabled, &d.RevokedAt, &d.Provider, &d.Sub, &d.Email, &routes, &d.ExpiresAt, &d.CreatedAt); err != nil {
		return d, err
	}
	d.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(routes), &d.Routes); err != nil {
		return d, fmt.Errorf("device %d: routes: %w", d.ID, err)
	}
	if plain, err := s.openSecret(psk, wgDevicePSKAAD(d.ID)); err == nil {
		d.PresharedKey = plain
	}
	return d, nil
}

// ListWGDevices returns every device, revoked ones included, with preshared
// keys: for the engine. The APIs blank the keys.
func (s *Store) ListWGDevices() ([]WGDevice, error) {
	rows, err := s.db.Query("SELECT " + wgDeviceCols + " FROM wg_devices ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WGDevice{}
	for rows.Next() {
		d, err := s.scanWGDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetWGDevice(id int64) (WGDevice, error) {
	return s.scanWGDevice(s.db.QueryRow("SELECT "+wgDeviceCols+" FROM wg_devices WHERE id=?", id))
}

// publicKeyTaken reports whether any site or device, revoked ones included,
// has this key (S3).
func publicKeyTaken(q dbtx, key string) (bool, error) {
	var n int
	err := q.QueryRow("SELECT (SELECT COUNT(*) FROM wg_sites WHERE public_key=?) + (SELECT COUNT(*) FROM wg_devices WHERE public_key=?)", key, key).Scan(&n)
	return n > 0, err
}

// ErrDeviceLimit is returned when an owner has as many devices as allowed.
var ErrDeviceLimit = errors.New("this account has as many devices as it may have")

// CreateWGDevice stores a device. The address is assigned here. limit > 0
// caps the owner's devices that are not revoked, checked in the same
// transaction as the insert.
func (s *Store) CreateWGDevice(d *WGDevice, tunnel netip.Prefix, psk string, limit int) error {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" || len(d.Name) > 64 {
		return errors.New("a device needs a name of at most 64 characters")
	}
	switch d.Kind {
	case "admin", "sso", "breakglass":
	default:
		return fmt.Errorf("unknown device kind %q", d.Kind)
	}
	for i := range d.Routes {
		if err := d.Routes[i].Validate(); err != nil {
			return err
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if taken, err := publicKeyTaken(tx, d.PublicKey); err != nil {
		return err
	} else if taken {
		return errors.New("this public key is already registered, or was and has been revoked: make a new key")
	}
	if limit > 0 {
		var n int
		if err := tx.QueryRow("SELECT COUNT(*) FROM wg_devices WHERE kind='sso' AND provider=? AND sub=? AND revoked_at=''", d.Provider, d.Sub).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return ErrDeviceLimit
		}
	}
	addr, err := nextWGAddress(tx, tunnel)
	if err != nil {
		return err
	}
	routes, _ := json.Marshal(d.Routes)
	ts := now()
	res, err := tx.Exec("INSERT INTO wg_devices (name, kind, public_key, psk, address, enabled, provider, sub, email, routes, expires_at, created_at) VALUES (?,?,?,'',?,?,?,?,?,?,?,?)",
		d.Name, d.Kind, d.PublicKey, addr.String(), b2i(d.Enabled), d.Provider, d.Sub, d.Email, string(routes), d.ExpiresAt, ts)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	sealed, err := s.sealSecret(psk, wgDevicePSKAAD(id))
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE wg_devices SET psk=? WHERE id=?", sealed, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.ID, d.Address, d.CreatedAt = id, addr.String(), ts
	return nil
}

// SetWGDeviceEnabled switches an admin's device on or off. A revoked device
// stays revoked.
func (s *Store) SetWGDeviceEnabled(id int64, enabled bool) error {
	res, err := s.db.Exec("UPDATE wg_devices SET enabled=? WHERE id=? AND revoked_at=''", b2i(enabled), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RevokeWGDevice ends a device for good. Its address is freed; its key stays,
// so it can never be registered again. owner, when set, restricts the call to
// that person's devices: the portal may only revoke its own.
func (s *Store) RevokeWGDevice(id int64, owner *VPNSubject) error {
	where := " WHERE id=? AND revoked_at=''"
	args := []any{id}
	if owner != nil {
		where += " AND kind='sso' AND provider=? AND sub=?"
		args = append(args, owner.Provider, owner.Sub)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The address stays out of use: see nextWGAddress.
	if _, err := tx.Exec("INSERT OR IGNORE INTO wg_freed (address) SELECT address FROM wg_devices"+where+" AND address IS NOT NULL", args...); err != nil {
		return err
	}
	res, err := tx.Exec("UPDATE wg_devices SET revoked_at=?, enabled=0, address=NULL"+where, append([]any{now()}, args...)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// ---- policies ----

func (s *Store) ListVPNPolicies() ([]VPNPolicy, error) {
	rows, err := s.db.Query("SELECT id, name, subject, routes FROM vpn_policies ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VPNPolicy{}
	for rows.Next() {
		var p VPNPolicy
		var subject, routes string
		if err := rows.Scan(&p.ID, &p.Name, &subject, &routes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(subject), &p.Subject); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(routes), &p.Routes); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SaveVPNPolicy(p *VPNPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := requireRow(s.db, "oidc_providers", p.Subject.Provider, "identity provider"); err != nil {
		return err
	}
	subject, _ := json.Marshal(p.Subject)
	routes, _ := json.Marshal(p.Routes)
	if p.ID == 0 {
		res, err := s.db.Exec("INSERT INTO vpn_policies (name, subject, routes) VALUES (?,?,?)", p.Name, string(subject), string(routes))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return errors.New("a policy with this name already exists")
			}
			return err
		}
		p.ID, _ = res.LastInsertId()
		return nil
	}
	res, err := s.db.Exec("UPDATE vpn_policies SET name=?, subject=?, routes=? WHERE id=?", p.Name, string(subject), string(routes), p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteVPNPolicy(id int64) error {
	res, err := s.db.Exec("DELETE FROM vpn_policies WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---- sessions ----

const vpnSessionCols = "id, provider, sub, email, groups, refresh_token, login_at, renewed_at, lease_until, grace_until, hard_until, transient, state, generation"

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

func (s *Store) scanVPNSession(row interface{ Scan(...any) error }) (VPNSession, error) {
	var v VPNSession
	var groups, token, login, renewed, lease, grace, hard string
	var transient int
	if err := row.Scan(&v.ID, &v.Provider, &v.Sub, &v.Email, &groups, &token, &login, &renewed, &lease, &grace, &hard, &transient, &v.State, &v.Generation); err != nil {
		return v, err
	}
	_ = json.Unmarshal([]byte(groups), &v.Groups)
	v.LoginAt, v.RenewedAt, v.LeaseUntil, v.GraceUntil, v.HardUntil = parseTS(login), parseTS(renewed), parseTS(lease), parseTS(grace), parseTS(hard)
	v.Transient = transient == 1
	if plain, err := s.openSecret(token, sessionTokenAAD(v.ID, v.Provider, v.Sub)); err == nil {
		v.RefreshToken = plain
	}
	return v, nil
}

func (s *Store) ListVPNSessions() ([]VPNSession, error) {
	rows, err := s.db.Query("SELECT " + vpnSessionCols + " FROM vpn_sessions ORDER BY email, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VPNSession{}
	for rows.Next() {
		v, err := s.scanVPNSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetVPNSession(provider int64, sub string) (VPNSession, error) {
	return s.scanVPNSession(s.db.QueryRow("SELECT "+vpnSessionCols+" FROM vpn_sessions WHERE provider=? AND sub=?", provider, sub))
}

// LoginVPNSession records a fresh login: it starts or restarts the owner's
// lease and the hard limit, and bumps the generation so that a renewal still
// in flight for the old state cannot commit (S44). It refuses a blocked owner.
func (s *Store) LoginVPNSession(v *VPNSession) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var blocked int
	if err := tx.QueryRow("SELECT COUNT(*) FROM vpn_blocked WHERE provider=? AND sub=?", v.Provider, v.Sub).Scan(&blocked); err != nil {
		return err
	}
	if blocked > 0 {
		return ErrOwnerBlocked
	}
	groups, _ := json.Marshal(v.Groups)
	var id, gen int64
	err = tx.QueryRow("SELECT id, generation FROM vpn_sessions WHERE provider=? AND sub=?", v.Provider, v.Sub).Scan(&id, &gen)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.Exec("INSERT INTO vpn_sessions (provider, sub, email, groups, login_at, renewed_at, lease_until, grace_until, hard_until, state, generation) VALUES (?,?,?,?,?,?,?,?,?,'active',1)",
			v.Provider, v.Sub, v.Email, string(groups), ts(v.LoginAt), ts(v.RenewedAt), ts(v.LeaseUntil), ts(v.GraceUntil), ts(v.HardUntil))
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		gen = 1
	case err != nil:
		return err
	default:
		gen++
		if _, err := tx.Exec("UPDATE vpn_sessions SET email=?, groups=?, login_at=?, renewed_at=?, lease_until=?, grace_until=?, hard_until=?, transient=0, state='active', generation=? WHERE id=?",
			v.Email, string(groups), ts(v.LoginAt), ts(v.RenewedAt), ts(v.LeaseUntil), ts(v.GraceUntil), ts(v.HardUntil), gen, id); err != nil {
			return err
		}
	}
	sealed, err := s.sealSecret(v.RefreshToken, sessionTokenAAD(id, v.Provider, v.Sub))
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE vpn_sessions SET refresh_token=? WHERE id=?", sealed, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	v.ID, v.Generation, v.State = id, gen, "active"
	return nil
}

// ErrOwnerBlocked is returned for a person an admin has blocked.
var ErrOwnerBlocked = errors.New("this account is blocked from the VPN")

// ErrStaleSession means the session changed while a renewal was under way, so
// the renewal's result is discarded (S44).
var ErrStaleSession = errors.New("the session changed while it was being renewed")

// RenewVPNSession commits a successful renewal, if and only if the session is
// still the one the renewal started from and still active. The new refresh
// token, the groups and the deadlines are written in the same statement.
func (s *Store) RenewVPNSession(v *VPNSession, fromGeneration int64) error {
	sealed, err := s.sealSecret(v.RefreshToken, sessionTokenAAD(v.ID, v.Provider, v.Sub))
	if err != nil {
		return err
	}
	groups, _ := json.Marshal(v.Groups)
	res, err := s.db.Exec("UPDATE vpn_sessions SET email=?, groups=?, refresh_token=?, renewed_at=?, lease_until=?, grace_until=?, transient=0, generation=generation+1 WHERE id=? AND generation=? AND state='active'",
		v.Email, string(groups), sealed, ts(v.RenewedAt), ts(v.LeaseUntil), ts(v.GraceUntil), v.ID, fromGeneration)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrStaleSession
	}
	v.Generation = fromGeneration + 1
	return nil
}

// MarkVPNSessionTransient notes that renewals are failing for reasons that say
// nothing about the account. It moves no deadline.
func (s *Store) MarkVPNSessionTransient(id, fromGeneration int64) error {
	_, err := s.db.Exec("UPDATE vpn_sessions SET transient=1 WHERE id=? AND generation=? AND state='active'", id, fromGeneration)
	return err
}

// EndVPNSession ends or lapses a session and forgets its refresh token. state
// is "ended" (logout, admin) or "lapsed" (refused by the provider, deadline).
// fromGeneration 0 ends it whatever its generation.
func (s *Store) EndVPNSession(id int64, state string, fromGeneration int64) error {
	q := "UPDATE vpn_sessions SET state=?, refresh_token='', transient=0, generation=generation+1 WHERE id=?"
	args := []any{state, id}
	if fromGeneration > 0 {
		q += " AND generation=?"
		args = append(args, fromGeneration)
	}
	_, err := s.db.Exec(q, args...)
	return err
}

// ---- blocked owners ----

type VPNBlocked struct {
	Provider  int64  `json:"provider"`
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	BlockedAt string `json:"blockedAt"`
}

func (s *Store) ListVPNBlocked() ([]VPNBlocked, error) {
	rows, err := s.db.Query("SELECT provider, sub, email, blocked_at FROM vpn_blocked ORDER BY email")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VPNBlocked{}
	for rows.Next() {
		var b VPNBlocked
		if err := rows.Scan(&b.Provider, &b.Sub, &b.Email, &b.BlockedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BlockVPNOwner blocks a person and ends their session in one transaction. A
// login does not undo it; only UnblockVPNOwner does (S43).
func (s *Store) BlockVPNOwner(provider int64, sub, email string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR REPLACE INTO vpn_blocked (provider, sub, email, blocked_at) VALUES (?,?,?,?)", provider, sub, email, now()); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE vpn_sessions SET state='ended', refresh_token='', generation=generation+1 WHERE provider=? AND sub=?", provider, sub); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnblockVPNOwner(provider int64, sub string) error {
	_, err := s.db.Exec("DELETE FROM vpn_blocked WHERE provider=? AND sub=?", provider, sub)
	return err
}

func (s *Store) VPNOwnerBlocked(provider int64, sub string) bool {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM vpn_blocked WHERE provider=? AND sub=?", provider, sub).Scan(&n)
	return n > 0
}

// PortalOptions configures a host of type vpn-portal: where people log in to
// enrol their devices and to renew their authorization (S22, S24).
type PortalOptions struct {
	ProviderID int64 `json:"providerId"`
	// ClaimsSource says where the groups come from when a lease is renewed:
	// the refreshed ID token, which the provider must then return, or the
	// provider's UserInfo endpoint (S45).
	ClaimsSource string `json:"claimsSource"` // id_token | userinfo
	// Enrol lists who may have devices at all (S53).
	Enrol []VPNSubject `json:"enrol"`
}

func (p *PortalOptions) Validate() error {
	if p.ProviderID <= 0 {
		return errors.New("the portal needs an identity provider")
	}
	switch p.ClaimsSource {
	case "":
		p.ClaimsSource = "id_token"
	case "id_token", "userinfo":
	default:
		return errors.New("claimsSource must be id_token or userinfo")
	}
	if len(p.Enrol) == 0 {
		return errors.New("say who may enrol devices: a group, a user, or every user of the provider")
	}
	for i := range p.Enrol {
		if err := p.Enrol[i].Validate(true); err != nil {
			return err
		}
		if p.Enrol[i].Provider != p.ProviderID {
			return errors.New("an enrolment subject must belong to the portal's identity provider")
		}
	}
	return nil
}
