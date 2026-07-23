package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// HeaderRule is one typed header mutation, applied in order.
type HeaderRule struct {
	Op    string `json:"op"` // set | add | remove
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// RateLimit is a per-client-IP token bucket for one host.
type RateLimit struct {
	RPS   float64 `json:"rps"`   // sustained requests per second
	Burst int     `json:"burst"` // bucket size
}

// Redirect describes where a redirect-type host sends visitors.
type Redirect struct {
	HTTPCode     int    `json:"httpCode"`     // 300, 301, 302, 307, 308
	TargetScheme string `json:"targetScheme"` // auto | http | https
	TargetHost   string `json:"targetHost"`
	PreservePath bool   `json:"preservePath"`
}

// HSTS holds the Strict-Transport-Security settings for a host.
type HSTS struct {
	Enabled           bool `json:"enabled"`
	MaxAge            int  `json:"maxAge"` // seconds
	IncludeSubdomains bool `json:"includeSubdomains"`
	Preload           bool `json:"preload"`
}

// Upstream is where a proxy host forwards to.
type Upstream struct {
	Scheme string `json:"scheme"` // http | https
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

// Options is the structured replacement for NPM's free-text advanced config.
// Zero values mean "engine default"; pointers distinguish unset from false.
type Options struct {
	// Upstream group
	PreserveHost             bool   `json:"preserveHost"`
	HostOverride             string `json:"hostOverride,omitempty"`
	SkipTLSVerify            bool   `json:"skipTlsVerify"`
	UpstreamSNI              string `json:"upstreamSni,omitempty"`
	DialTimeoutSec           int    `json:"dialTimeoutSec,omitempty"`
	ResponseHeaderTimeoutSec int    `json:"responseHeaderTimeoutSec,omitempty"`
	IdleTimeoutSec           int    `json:"idleTimeoutSec,omitempty"`
	MaxBodyMB                int    `json:"maxBodyMb,omitempty"` // 0 = unlimited
	Buffering                *bool  `json:"buffering,omitempty"` // nil/true = buffered; false = flush immediately (SSE)

	// Request / response groups
	RequestHeaders  []HeaderRule `json:"requestHeaders,omitempty"`
	ResponseHeaders []HeaderRule `json:"responseHeaders,omitempty"`

	// Security group
	BlockIndexing bool       `json:"blockIndexing"` // send X-Robots-Tag: noindex, nofollow
	BlockExploits bool       `json:"blockExploits"` // filter common attack patterns
	RateLimit     *RateLimit `json:"rateLimit,omitempty"`

	// Response group
	Compression bool `json:"compression"` // gzip responses when the client accepts it

	// TLS group
	HSTS          HSTS   `json:"hsts"`
	MinTLSVersion string `json:"minTlsVersion,omitempty"` // "" (default 1.2) | "1.2" | "1.3"
	HTTP3         *bool  `json:"http3,omitempty"`         // nil/true = advertise h3
}

// Host is one configured host of any type. M1 implements type "proxy".
type Host struct {
	ID           int64     `json:"id"`
	Type         string    `json:"type"` // proxy | redirect | dead
	Domains      []string  `json:"domains"`
	Upstream     Upstream  `json:"upstream"`
	Redirect     *Redirect `json:"redirect,omitempty"`
	CertMode     string    `json:"certMode"` // auto (ACME) | none (plain http) | custom
	CertID       *int64    `json:"certId"`   // when certMode=custom
	ForceSSL     bool      `json:"forceSsl"`
	Enabled      bool      `json:"enabled"`
	AccessListID *int64    `json:"accessListId"`
	Options      Options   `json:"options"`
	CreatedAt    string    `json:"createdAt,omitempty"`
	UpdatedAt    string    `json:"updatedAt,omitempty"`
}

// AccessRule is one ordered CIDR rule; first match wins, no match denies.
type AccessRule struct {
	Action string `json:"action"` // allow | deny
	CIDR   string `json:"cidr"`
}

// AccessUser carries a plaintext Password only inbound from the API; at rest
// and outbound only Username and the bcrypt hash (never serialized) exist.
type AccessUser struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"` // API input only
	Hash     string `json:"-"`
}

// AccessList mirrors NPM's access lists: CIDR rules + basic auth users.
type AccessList struct {
	ID       int64        `json:"id"`
	Name     string       `json:"name"`
	Satisfy  string       `json:"satisfy"` // any | all
	PassAuth bool         `json:"passAuth"`
	Rules    []AccessRule `json:"rules"`
	Users    []AccessUser `json:"users"`
}

// Stream is one TCP/UDP port forward. AllowedCIDRs is a source whitelist:
// empty = anyone (needed since UPnP may expose the port to the WAN),
// non-empty = only matching sources, everything else dropped at accept time.
type Stream struct {
	ID           int64    `json:"id"`
	ListenPort   int      `json:"listenPort"`
	Protocol     string   `json:"protocol"` // tcp | udp | both
	ForwardHost  string   `json:"forwardHost"`
	ForwardPort  int      `json:"forwardPort"`
	AllowedCIDRs []string `json:"allowedCidrs"`
	Enabled      bool     `json:"enabled"`
	CreatedAt    string   `json:"createdAt,omitempty"`
	UpdatedAt    string   `json:"updatedAt,omitempty"`
}

type User struct {
	ID         int64
	Email      string
	Hash       string
	MustChange bool
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^localhost$`)

// Validate checks a host before it is persisted; every rule here backs a
// server-side rejection so the UI can never save a broken config.
func (h *Host) Validate() error {
	if h.Type == "" {
		h.Type = "proxy"
	}
	if h.Type != "proxy" && h.Type != "redirect" && h.Type != "dead" {
		return fmt.Errorf("unsupported host type %q", h.Type)
	}
	if len(h.Domains) == 0 {
		return errors.New("at least one domain is required")
	}
	for i, d := range h.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		h.Domains[i] = d
		if !domainRe.MatchString(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
	}
	switch h.Type {
	case "proxy":
		h.Redirect = nil
		if h.Upstream.Scheme != "http" && h.Upstream.Scheme != "https" {
			return fmt.Errorf("upstream scheme must be http or https, got %q", h.Upstream.Scheme)
		}
		if strings.TrimSpace(h.Upstream.Host) == "" {
			return errors.New("upstream host is required")
		}
		if h.Upstream.Port < 1 || h.Upstream.Port > 65535 {
			return fmt.Errorf("upstream port %d out of range", h.Upstream.Port)
		}
	case "redirect":
		h.Upstream = Upstream{}
		if h.Redirect == nil {
			return errors.New("redirect host needs a redirect target")
		}
		switch h.Redirect.HTTPCode {
		case 0:
			h.Redirect.HTTPCode = 301
		case 300, 301, 302, 307, 308:
		default:
			return fmt.Errorf("redirect code must be 300/301/302/307/308, got %d", h.Redirect.HTTPCode)
		}
		switch h.Redirect.TargetScheme {
		case "":
			h.Redirect.TargetScheme = "auto"
		case "auto", "http", "https":
		default:
			return fmt.Errorf("redirect scheme must be auto, http or https, got %q", h.Redirect.TargetScheme)
		}
		if strings.TrimSpace(h.Redirect.TargetHost) == "" {
			return errors.New("redirect target host is required")
		}
	case "dead":
		h.Upstream = Upstream{}
		h.Redirect = nil
	}
	if rl := h.Options.RateLimit; rl != nil {
		if rl.RPS <= 0 {
			return errors.New("rate limit rps must be positive")
		}
		if rl.Burst < 1 {
			rl.Burst = int(rl.RPS)
			if rl.Burst < 1 {
				rl.Burst = 1
			}
		}
	}
	if h.CertMode == "" {
		h.CertMode = "auto"
	}
	if h.CertMode != "auto" && h.CertMode != "none" && h.CertMode != "custom" {
		return fmt.Errorf("certMode must be auto, none or custom, got %q", h.CertMode)
	}
	if h.CertMode == "custom" && h.CertID == nil {
		return errors.New("certMode custom requires a certificate")
	}
	if h.CertMode != "custom" {
		h.CertID = nil
	}
	if h.CertMode == "none" && h.ForceSSL {
		return errors.New("forceSsl requires TLS")
	}
	return h.Options.validate()
}

func (o *Options) validate() error {
	for _, rules := range [][]HeaderRule{o.RequestHeaders, o.ResponseHeaders} {
		for _, r := range rules {
			if r.Op != "set" && r.Op != "add" && r.Op != "remove" {
				return fmt.Errorf("header rule op must be set, add or remove, got %q", r.Op)
			}
			if strings.TrimSpace(r.Name) == "" {
				return errors.New("header rule name is required")
			}
		}
	}
	switch o.MinTLSVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("minTlsVersion must be 1.2 or 1.3, got %q", o.MinTLSVersion)
	}
	if o.HSTS.Enabled && o.HSTS.MaxAge <= 0 {
		o.HSTS.MaxAge = 15552000 // 180 days, NPM's default
	}
	for name, v := range map[string]int{
		"dialTimeoutSec": o.DialTimeoutSec, "responseHeaderTimeoutSec": o.ResponseHeaderTimeoutSec,
		"idleTimeoutSec": o.IdleTimeoutSec, "maxBodyMb": o.MaxBodyMB,
	} {
		if v < 0 {
			return fmt.Errorf("%s cannot be negative", name)
		}
	}
	return nil
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc sqlite: single writer keeps things simple and safe
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL DEFAULT 'proxy',
  domains TEXT NOT NULL,
  upstream TEXT NOT NULL,
  cert_mode TEXT NOT NULL DEFAULT 'auto',
  force_ssl INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  options TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  hash TEXT NOT NULL,
  must_change INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS access_lists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  satisfy TEXT NOT NULL DEFAULT 'any',
  pass_auth INTEGER NOT NULL DEFAULT 0,
  rules TEXT NOT NULL DEFAULT '[]',
  users TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS streams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  listen_port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  fwd_host TEXT NOT NULL,
  fwd_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	// Older databases lack later columns; duplicate-column errors are fine.
	for _, stmt := range []string{
		"ALTER TABLE hosts ADD COLUMN access_list_id INTEGER",
		"ALTER TABLE streams ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE hosts ADD COLUMN redirect TEXT NOT NULL DEFAULT 'null'",
		"ALTER TABLE hosts ADD COLUMN cert_id INTEGER",
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return s.migrateCustomCerts()
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var domains, upstream, options, redirect string
	var forceSSL, enabled int
	err := row.Scan(&h.ID, &h.Type, &domains, &upstream, &h.CertMode, &forceSSL, &enabled, &options, &h.CreatedAt, &h.UpdatedAt, &h.AccessListID, &redirect, &h.CertID)
	if err != nil {
		return h, err
	}
	h.ForceSSL = forceSSL == 1
	h.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(domains), &h.Domains); err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(upstream), &h.Upstream); err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(options), &h.Options); err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(redirect), &h.Redirect); err != nil {
		return h, err
	}
	return h, nil
}

const hostCols = "id, type, domains, upstream, cert_mode, force_ssl, enabled, options, created_at, updated_at, access_list_id, redirect, cert_id"

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query("SELECT " + hostCols + " FROM hosts ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(id int64) (Host, error) {
	return scanHost(s.db.QueryRow("SELECT "+hostCols+" FROM hosts WHERE id = ?", id))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) CreateHost(h *Host) error {
	if err := h.Validate(); err != nil {
		return err
	}
	domains, _ := json.Marshal(h.Domains)
	upstream, _ := json.Marshal(h.Upstream)
	options, _ := json.Marshal(h.Options)
	redirect, _ := json.Marshal(h.Redirect)
	h.CreatedAt, h.UpdatedAt = now(), now()
	res, err := s.db.Exec(
		"INSERT INTO hosts (type, domains, upstream, cert_mode, force_ssl, enabled, options, created_at, updated_at, access_list_id, redirect, cert_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
		h.Type, string(domains), string(upstream), h.CertMode, b2i(h.ForceSSL), b2i(h.Enabled), string(options), h.CreatedAt, h.UpdatedAt, h.AccessListID, string(redirect), h.CertID)
	if err != nil {
		return err
	}
	h.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateHost(h *Host) error {
	if err := h.Validate(); err != nil {
		return err
	}
	domains, _ := json.Marshal(h.Domains)
	upstream, _ := json.Marshal(h.Upstream)
	options, _ := json.Marshal(h.Options)
	redirect, _ := json.Marshal(h.Redirect)
	h.UpdatedAt = now()
	res, err := s.db.Exec(
		"UPDATE hosts SET type=?, domains=?, upstream=?, cert_mode=?, force_ssl=?, enabled=?, options=?, updated_at=?, access_list_id=?, redirect=?, cert_id=? WHERE id=?",
		h.Type, string(domains), string(upstream), h.CertMode, b2i(h.ForceSSL), b2i(h.Enabled), string(options), h.UpdatedAt, h.AccessListID, string(redirect), h.CertID, h.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteHost(id int64) error {
	res, err := s.db.Exec("DELETE FROM hosts WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (s *Store) GetUserByEmail(email string) (User, error) {
	var u User
	var mc int
	err := s.db.QueryRow("SELECT id, email, hash, must_change FROM users WHERE email=?", strings.ToLower(email)).
		Scan(&u.ID, &u.Email, &u.Hash, &mc)
	u.MustChange = mc == 1
	return u, err
}

func (s *Store) CreateUser(email, hash string, mustChange bool) error {
	_, err := s.db.Exec("INSERT INTO users (email, hash, must_change) VALUES (?,?,?)", strings.ToLower(email), hash, b2i(mustChange))
	return err
}

func (s *Store) SetPassword(id int64, hash string) error {
	_, err := s.db.Exec("UPDATE users SET hash=?, must_change=0 WHERE id=?", hash, id)
	return err
}

// GetSetting returns a stored setting or def if unset.
func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&v); err != nil {
		return def
	}
	return v
}

// AllSettings returns every stored setting as a map.
func (s *Store) AllSettings() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSetting upserts one setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		key, value)
	return err
}

// Snapshot writes a consistent copy of the database to path.
func (s *Store) Snapshot(path string) error {
	_, err := s.db.Exec("VACUUM INTO ?", path)
	return err
}

var backupTables = []string{"hosts", "users", "access_lists", "streams", "settings", "custom_certs"}

// RestoreFrom replaces all configuration with the contents of the snapshot
// database at dbPath, atomically. Fails cleanly (nothing changed) when the
// snapshot's schema does not match this binary's.
func (s *Store) RestoreFrom(dbPath string) error {
	if _, err := s.db.Exec("ATTACH ? AS backup", dbPath); err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer s.db.Exec("DETACH backup")
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, t := range backupTables {
		if _, err := tx.Exec("DELETE FROM " + t); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec("INSERT INTO " + t + " SELECT * FROM backup." + t); err != nil {
			tx.Rollback()
			return fmt.Errorf("restore %s (schema mismatch between backup and this version?): %w", t, err)
		}
	}
	return tx.Commit()
}
