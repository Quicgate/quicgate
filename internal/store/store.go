package store

import (
	"crypto/x509"
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

// PathRewrite rewrites the request path before it reaches the upstream.
// Applied in order: strip prefix, add prefix, then regex replace.
type PathRewrite struct {
	StripPrefix string `json:"stripPrefix,omitempty"`
	AddPrefix   string `json:"addPrefix,omitempty"`
	Regex       string `json:"regex,omitempty"`       // RE2
	Replacement string `json:"replacement,omitempty"` // $1, $2 supported
}

// Location routes a path prefix on a proxy host to its own upstream, with an
// optional path rewrite (NPM's "custom locations", done right).
type Location struct {
	Path        string       `json:"path"` // matched as a prefix; longest wins
	Upstream    Upstream     `json:"upstream"`
	PathRewrite *PathRewrite `json:"pathRewrite,omitempty"`
}

// RateLimit is a per-client-IP token bucket for one host.
type RateLimit struct {
	RPS   float64 `json:"rps"`   // sustained requests per second
	Burst int     `json:"burst"` // bucket size
}

// ForwardAuth delegates per-request authorization to an external endpoint
// (Authelia / Authentik / Keycloak-style), mirroring Traefik's forwardAuth.
type ForwardAuth struct {
	URL             string   `json:"url"`             // auth endpoint
	ResponseHeaders []string `json:"responseHeaders"` // copied from auth 2xx to upstream request
	SkipTLSVerify   bool     `json:"skipTlsVerify"`   // for https auth endpoints with self-signed certs
}

// AuthRule scopes authentication to a URL path, so one host can keep a few
// endpoints reachable without credentials while everything else stays behind
// an access list or forward auth (a licensing callback, a webhook, a health
// probe). Rules are matched longest-path-first; a request matching no rule
// falls back to the host's own access list and forward-auth settings.
type AuthRule struct {
	Path         string `json:"path"`                   // matched as a prefix unless Exact
	Exact        bool   `json:"exact,omitempty"`        // match this exact path only
	Mode         string `json:"mode"`                   // public | accessList | forwardAuth | oidc
	AccessListID *int64 `json:"accessListId,omitempty"` // required when mode=accessList
	// OIDC, when set on a mode=oidc rule, gates this path with its own
	// identity provider and policy instead of the host's. That is how one host
	// can put staff behind the work IdP and a partner endpoint behind another,
	// or use a separate app registration per URL on the same IdP.
	OIDC    *OIDCAuth `json:"oidc,omitempty"`
	Methods []string  `json:"methods,omitempty"` // empty = every method
}

// ClientCert configures mutual TLS for a host.
type ClientCert struct {
	Mode  string `json:"mode"`  // require | request
	CAPEM string `json:"caPem"` // PEM bundle of accepted client CAs
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
	MaxIdleConnsPerHost      int    `json:"maxIdleConnsPerHost,omitempty"`
	MaxBodyMB                int    `json:"maxBodyMb,omitempty"` // 0 = unlimited
	Buffering                *bool  `json:"buffering,omitempty"` // nil/true = buffered; false = flush immediately (SSE)

	// Request / response groups
	RequestHeaders  []HeaderRule `json:"requestHeaders,omitempty"`
	ResponseHeaders []HeaderRule `json:"responseHeaders,omitempty"`
	PathRewrite     *PathRewrite `json:"pathRewrite,omitempty"`

	// Security group
	BlockIndexing bool         `json:"blockIndexing"` // send X-Robots-Tag: noindex, nofollow
	BlockExploits bool         `json:"blockExploits"` // filter common attack patterns
	BlockBadBots  bool         `json:"blockBadBots"`  // block known scraper/bot user-agents
	RateLimit     *RateLimit   `json:"rateLimit,omitempty"`
	ForwardAuth   *ForwardAuth `json:"forwardAuth,omitempty"`
	OIDC          *OIDCAuth    `json:"oidc,omitempty"`       // built-in OpenID Connect SSO
	AuthRules     []AuthRule   `json:"authRules,omitempty"`  // path-scoped overrides of the gates above
	ClientCert    *ClientCert  `json:"clientCert,omitempty"` // mTLS

	// Response group (continued)
	BadGatewayHTML string `json:"badGatewayHtml,omitempty"` // custom upstream-down page

	// Response group
	Compression bool `json:"compression"` // gzip responses when the client accepts it

	// Behaviour group
	Maintenance     bool   `json:"maintenance"`               // serve a 503 maintenance page instead of proxying
	MaintenanceHTML string `json:"maintenanceHtml,omitempty"` // custom maintenance page body
	StickySessions  bool   `json:"stickySessions"`            // cookie session affinity across the upstream pool
	CacheSec        int    `json:"cacheSec,omitempty"`        // >0 = cache cacheable GET/HEAD responses this many seconds

	// TLS group
	HSTS          HSTS   `json:"hsts"`
	MinTLSVersion string `json:"minTlsVersion,omitempty"` // "" (default 1.2) | "1.2" | "1.3"
	HTTP3         *bool  `json:"http3,omitempty"`         // nil/true = advertise h3
}

// Host is one configured host of any type. M1 implements type "proxy".
type Host struct {
	ID           int64      `json:"id"`
	Type         string     `json:"type"` // proxy | redirect | dead | static
	Domains      []string   `json:"domains"`
	Upstream     Upstream   `json:"upstream"`            // primary target
	Upstreams    []Upstream `json:"upstreams,omitempty"` // load-balancing pool (optional)
	Locations    []Location `json:"locations,omitempty"` // path-prefix routes to other upstreams
	Redirect     *Redirect  `json:"redirect,omitempty"`
	StaticRoot   string     `json:"staticRoot,omitempty"` // when type=static
	CertMode     string     `json:"certMode"`             // auto (ACME) | none (plain http) | custom
	CertID       *int64     `json:"certId"`               // when certMode=custom
	ForceSSL     bool       `json:"forceSsl"`
	Enabled      bool       `json:"enabled"`
	AccessListID *int64     `json:"accessListId"`
	Options      Options    `json:"options"`
	CreatedAt    string     `json:"createdAt,omitempty"`
	UpdatedAt    string     `json:"updatedAt,omitempty"`
}

// AccessRule is one ordered rule; first match wins, no match denies. Exactly
// one of CIDR, Host (dynamic DNS) or Country (GeoIP) is set.
type AccessRule struct {
	Action  string `json:"action"` // allow | deny
	CIDR    string `json:"cidr,omitempty"`
	Host    string `json:"host,omitempty"`    // hostname, re-resolved periodically
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2, needs GeoIP DB
	// Methods scopes the rule to specific HTTP verbs (e.g. keep GET public
	// but require auth for POST/PUT/DELETE). Empty = every method.
	Methods []string `json:"methods,omitempty"`
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

// SNIRoute maps a TLS SNI hostname to a backend for SNI-based passthrough
// routing (many TLS services sharing one port without termination).
type SNIRoute struct {
	Host        string `json:"host"`
	ForwardHost string `json:"forwardHost"`
	ForwardPort int    `json:"forwardPort"`
}

// Stream is one TCP/UDP port forward. AllowedCIDRs is a source whitelist:
// empty = anyone (needed since UPnP may expose the port to the WAN),
// non-empty = only matching sources, everything else dropped at accept time.
type Stream struct {
	ID            int64    `json:"id"`
	ListenPort    int      `json:"listenPort"`
	ListenPortEnd int      `json:"listenPortEnd,omitempty"` // >0: listen on the whole range
	Protocol      string   `json:"protocol"`                // tcp | udp | both
	ForwardHost   string   `json:"forwardHost"`
	ForwardPort   int      `json:"forwardPort"`
	AllowedCIDRs  []string `json:"allowedCidrs"`
	// AccessListID, when set, reuses that access list's allow CIDR/host rules
	// as the source filter instead of AllowedCIDRs (define an allowlist once).
	AccessListID *int64 `json:"accessListId,omitempty"`

	// Round-2 options (all TCP-only).
	SendProxyProtocol   string `json:"sendProxyProtocol,omitempty"`   // "" | v1 | v2 (prepend PROXY header to backend)
	AcceptProxyProtocol bool   `json:"acceptProxyProtocol,omitempty"` // parse inbound PROXY header for real client IP
	// TrustedProxies lists the peers (CIDRs) whose PROXY header is believed and
	// required. Any other peer is treated as a direct client: its own socket
	// address is its identity and nothing it sends is parsed as a header.
	TrustedProxies []string   `json:"trustedProxies,omitempty"`
	TerminateTLS   bool       `json:"terminateTls,omitempty"` // terminate TLS with CertID, forward plaintext
	CertID         *int64     `json:"certId,omitempty"`
	SNIRoutes      []SNIRoute `json:"sniRoutes,omitempty"` // TLS passthrough by SNI

	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type User struct {
	ID         int64
	Email      string
	Hash       string
	MustChange bool
	TOTPSecret string // empty = 2FA disabled
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^localhost$`)

// Validate checks a host before it is persisted; every rule here backs a
// server-side rejection so the UI can never save a broken config.
func (h *Host) Validate() error {
	if h.Type == "" {
		h.Type = "proxy"
	}
	if h.Type != "proxy" && h.Type != "redirect" && h.Type != "dead" && h.Type != "static" {
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
		h.StaticRoot = ""
		validateUpstream := func(u Upstream) error {
			if u.Scheme != "http" && u.Scheme != "https" {
				return fmt.Errorf("upstream scheme must be http or https, got %q", u.Scheme)
			}
			if strings.TrimSpace(u.Host) == "" {
				return errors.New("upstream host is required")
			}
			if u.Port < 1 || u.Port > 65535 {
				return fmt.Errorf("upstream port %d out of range", u.Port)
			}
			return nil
		}
		if err := validateUpstream(h.Upstream); err != nil {
			return err
		}
		for i, u := range h.Upstreams {
			if err := validateUpstream(u); err != nil {
				return fmt.Errorf("pool upstream %d: %w", i+1, err)
			}
			if u.Scheme != h.Upstream.Scheme {
				return errors.New("all pool upstreams must share the primary's scheme")
			}
		}
		for i := range h.Locations {
			loc := &h.Locations[i]
			if !strings.HasPrefix(loc.Path, "/") {
				return fmt.Errorf("location %d: path must start with /", i+1)
			}
			if err := validateUpstream(loc.Upstream); err != nil {
				return fmt.Errorf("location %d: %w", i+1, err)
			}
			if err := validateRewrite(loc.PathRewrite); err != nil {
				return fmt.Errorf("location %d: %w", i+1, err)
			}
		}
		if err := validateRewrite(h.Options.PathRewrite); err != nil {
			return err
		}
	case "static":
		h.Redirect = nil
		h.Upstream = Upstream{}
		h.Upstreams = nil
		if strings.TrimSpace(h.StaticRoot) == "" {
			return errors.New("static host needs a root directory")
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
		h.Upstreams = nil
		h.Redirect = nil
		h.StaticRoot = ""
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
	if h.CertMode == "none" && h.Options.ClientCert != nil {
		return errors.New("client certificates require TLS; certMode none serves plain HTTP only")
	}
	return h.Options.validate()
}

func validateRewrite(pr *PathRewrite) error {
	if pr == nil {
		return nil
	}
	if pr.Regex != "" {
		if _, err := regexp.Compile(pr.Regex); err != nil {
			return fmt.Errorf("invalid path-rewrite regex: %w", err)
		}
	}
	return nil
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
	if cc := o.ClientCert; cc != nil {
		switch cc.Mode {
		case "":
			cc.Mode = "require"
		case "require", "request":
		default:
			return fmt.Errorf("clientCert mode must be require or request, got %q", cc.Mode)
		}
		// A bundle that yields no CA would leave the policy unenforceable, so it
		// is refused here rather than silently accepted.
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(cc.CAPEM)) {
			return errors.New("clientCert needs a PEM bundle with at least one valid CA certificate")
		}
	}
	if o.HSTS.Enabled && o.HSTS.MaxAge <= 0 {
		o.HSTS.MaxAge = 15552000 // 180 days, NPM's default
	}
	if o.OIDC != nil {
		if err := o.OIDC.validate(); err != nil {
			return err
		}
	}
	if err := o.validateAuthRules(); err != nil {
		return err
	}
	for name, v := range map[string]int{
		"dialTimeoutSec": o.DialTimeoutSec, "responseHeaderTimeoutSec": o.ResponseHeaderTimeoutSec,
		"idleTimeoutSec": o.IdleTimeoutSec, "maxIdleConnsPerHost": o.MaxIdleConnsPerHost,
		"maxBodyMb": o.MaxBodyMB, "cacheSec": o.CacheSec,
	} {
		if v < 0 {
			return fmt.Errorf("%s cannot be negative", name)
		}
	}
	return nil
}

// validateAuthRules checks the path-scoped auth overrides. A rule that names a
// mode the engine does not know would silently gate nothing, so every field is
// checked here rather than shrugged off at request time.
func (o *Options) validateAuthRules() error {
	for i := range o.AuthRules {
		r := &o.AuthRules[i]
		r.Path = strings.TrimSpace(r.Path)
		if !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("auth rule %d: path must start with /", i+1)
		}
		switch r.Mode {
		case "public":
			r.AccessListID = nil
			r.OIDC = nil
		case "forwardAuth":
			r.AccessListID = nil
			r.OIDC = nil
			if o.ForwardAuth == nil || strings.TrimSpace(o.ForwardAuth.URL) == "" {
				return fmt.Errorf("auth rule %d: mode forwardAuth needs forward authentication configured on this host", i+1)
			}
		case "oidc":
			r.AccessListID = nil
			if r.OIDC != nil {
				if err := r.OIDC.validate(); err != nil {
					return fmt.Errorf("auth rule %d: %w", i+1, err)
				}
			} else if o.OIDC == nil {
				return fmt.Errorf("auth rule %d: mode oidc needs an identity provider on the rule or OIDC SSO on this host", i+1)
			}
		case "accessList":
			r.OIDC = nil
			if r.AccessListID == nil {
				return fmt.Errorf("auth rule %d: mode accessList needs an access list", i+1)
			}
		default:
			return fmt.Errorf("auth rule %d: mode must be public, accessList, forwardAuth or oidc, got %q", i+1, r.Mode)
		}
		if len(r.Methods) > 0 {
			methods := make([]string, 0, len(r.Methods))
			for _, m := range r.Methods {
				m = strings.ToUpper(strings.TrimSpace(m))
				if m == "" {
					continue
				}
				if !validHTTPMethods[m] {
					return fmt.Errorf("auth rule %d: unknown HTTP method %q", i+1, m)
				}
				methods = append(methods, m)
			}
			r.Methods = methods
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
CREATE TABLE IF NOT EXISTS port_forwards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ext_port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  int_ip TEXT NOT NULL,
  int_port INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oidc_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL DEFAULT '',
  scopes TEXT NOT NULL DEFAULT '',
  groups_claim TEXT NOT NULL DEFAULT 'groups',
  session_hours INTEGER NOT NULL DEFAULT 12,
  skip_tls_verify INTEGER NOT NULL DEFAULT 0
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
		"ALTER TABLE hosts ADD COLUMN upstreams TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE hosts ADD COLUMN static_root TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE streams ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE hosts ADD COLUMN locations TEXT NOT NULL DEFAULT '[]'",
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	if err := s.migrateCustomCerts(); err != nil {
		return err
	}
	return s.migrateTokens()
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var domains, upstream, options, redirect, upstreams, locations string
	var forceSSL, enabled int
	err := row.Scan(&h.ID, &h.Type, &domains, &upstream, &h.CertMode, &forceSSL, &enabled, &options, &h.CreatedAt, &h.UpdatedAt, &h.AccessListID, &redirect, &h.CertID, &upstreams, &h.StaticRoot, &locations)
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(locations), &h.Locations); err != nil {
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
	if err := json.Unmarshal([]byte(upstreams), &h.Upstreams); err != nil {
		return h, err
	}
	return h, nil
}

const hostCols = "id, type, domains, upstream, cert_mode, force_ssl, enabled, options, created_at, updated_at, access_list_id, redirect, cert_id, upstreams, static_root, locations"

func (s *Store) ListHosts() ([]Host, error) { return listHosts(s.db) }

func listHosts(q dbtx) ([]Host, error) {
	rows, err := q.Query("SELECT " + hostCols + " FROM hosts ORDER BY id")
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

func (s *Store) CreateHost(h *Host) error { return createHost(s.db, h) }

func createHost(q dbtx, h *Host) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if err := checkHostRefs(q, h); err != nil {
		return err
	}
	domains, _ := json.Marshal(h.Domains)
	upstream, _ := json.Marshal(h.Upstream)
	options, _ := json.Marshal(h.Options)
	redirect, _ := json.Marshal(h.Redirect)
	upstreams, _ := json.Marshal(h.Upstreams)
	locations, _ := json.Marshal(h.Locations)
	h.CreatedAt, h.UpdatedAt = now(), now()
	res, err := q.Exec(
		"INSERT INTO hosts (type, domains, upstream, cert_mode, force_ssl, enabled, options, created_at, updated_at, access_list_id, redirect, cert_id, upstreams, static_root, locations) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		h.Type, string(domains), string(upstream), h.CertMode, b2i(h.ForceSSL), b2i(h.Enabled), string(options), h.CreatedAt, h.UpdatedAt, h.AccessListID, string(redirect), h.CertID, string(upstreams), h.StaticRoot, string(locations))
	if err != nil {
		return err
	}
	h.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateHost(h *Host) error { return updateHost(s.db, h) }

func updateHost(q dbtx, h *Host) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if err := checkHostRefs(q, h); err != nil {
		return err
	}
	domains, _ := json.Marshal(h.Domains)
	upstream, _ := json.Marshal(h.Upstream)
	options, _ := json.Marshal(h.Options)
	redirect, _ := json.Marshal(h.Redirect)
	upstreams, _ := json.Marshal(h.Upstreams)
	locations, _ := json.Marshal(h.Locations)
	h.UpdatedAt = now()
	res, err := q.Exec(
		"UPDATE hosts SET type=?, domains=?, upstream=?, cert_mode=?, force_ssl=?, enabled=?, options=?, updated_at=?, access_list_id=?, redirect=?, cert_id=?, upstreams=?, static_root=?, locations=? WHERE id=?",
		h.Type, string(domains), string(upstream), h.CertMode, b2i(h.ForceSSL), b2i(h.Enabled), string(options), h.UpdatedAt, h.AccessListID, string(redirect), h.CertID, string(upstreams), h.StaticRoot, string(locations), h.ID)
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
	err := s.db.QueryRow("SELECT id, email, hash, must_change, totp_secret FROM users WHERE email=?", strings.ToLower(email)).
		Scan(&u.ID, &u.Email, &u.Hash, &mc, &u.TOTPSecret)
	u.MustChange = mc == 1
	return u, err
}

// SetTOTPSecret enables 2FA (secret set) or disables it (empty).
func (s *Store) SetTOTPSecret(id int64, secret string) error {
	_, err := s.db.Exec("UPDATE users SET totp_secret=? WHERE id=?", secret, id)
	return err
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

// RestoreFrom replaces every configuration table with the contents of the
// snapshot database at dbPath, in one transaction: on any error nothing changes.
//
// The tables come from this binary's own schema, so a table added later (API
// tokens, port forwards) can never be left out of a restore by a hand-kept
// list. A table the snapshot predates is emptied rather than kept, because the
// restored state must be the snapshot's and never a mix with live rows (live
// API tokens surviving a restore would be exactly that). Columns are matched by
// name, so an older snapshot restores into a newer schema with defaults for the
// columns it lacks. It returns warnings about references in the snapshot that
// do not resolve; the engine fails closed on those.
func (s *Store) RestoreFrom(dbPath string) ([]string, error) {
	if _, err := s.db.Exec("ATTACH ? AS backup", dbPath); err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}
	defer s.db.Exec("DETACH backup")
	var check string
	if err := s.db.QueryRow("PRAGMA backup.quick_check").Scan(&check); err != nil || check != "ok" {
		return nil, fmt.Errorf("snapshot database failed its integrity check: %v %s", err, check)
	}
	tables, err := tableNames(s.db, "main")
	if err != nil {
		return nil, err
	}
	backupTables, err := tableNames(s.db, "backup")
	if err != nil {
		return nil, err
	}
	inBackup := map[string]bool{}
	for _, t := range backupTables {
		inBackup[t] = true
	}
	// Refuse anything that is not a quicgate backup before touching live rows:
	// every table missing from the snapshot is emptied, and a table that shares
	// no columns with the schema restores no rows, so an unrelated SQLite file
	// would wipe the configuration and the admin account. These tables and
	// columns exist in every version's schema.
	for table, cols := range map[string][]string{
		"hosts": {"id", "type", "domains", "upstream"},
		"users": {"id", "email", "hash"},
	} {
		if !inBackup[table] {
			return nil, fmt.Errorf("this is not a quicgate backup: it has no %s table", table)
		}
		have, err := columnSet(s.db, "backup", table)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			if !have[c] {
				return nil, fmt.Errorf("this is not a quicgate backup: its %s table has no %s column", table, c)
			}
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // no-op after a successful commit
	for _, t := range tables {
		if _, err := tx.Exec("DELETE FROM " + quoteIdent(t)); err != nil {
			return nil, err
		}
		if !inBackup[t] {
			continue
		}
		cols, err := sharedColumns(tx, t)
		if err != nil {
			return nil, err
		}
		if len(cols) == 0 {
			continue
		}
		list := strings.Join(cols, ", ")
		if _, err := tx.Exec("INSERT INTO " + quoteIdent(t) + " (" + list + ") SELECT " + list + " FROM backup." + quoteIdent(t)); err != nil {
			return nil, fmt.Errorf("restore %s (schema mismatch between backup and this version?): %w", t, err)
		}
	}
	// The restored state must leave someone able to sign in: without an account
	// the operator is locked out, and the next start would recreate the
	// default credentials.
	var admins int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users WHERE email <> '' AND hash <> ''").Scan(&admins); err != nil {
		return nil, err
	}
	if admins == 0 {
		return nil, fmt.Errorf("the backup has no admin account that can sign in")
	}
	warnings, err := danglingReferences(tx)
	if err != nil {
		return nil, err
	}
	return warnings, tx.Commit()
}

// columnSet returns the column names of table in an attached schema.
func columnSet(q dbtx, schema, table string) (map[string]bool, error) {
	rows, err := q.Query("PRAGMA " + schema + ".table_info(" + quoteIdent(table) + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		set[name] = true
	}
	return set, rows.Err()
}

// tableNames lists the user tables of an attached schema (never SQLite's own).
func tableNames(q dbtx, schema string) ([]string, error) {
	rows, err := q.Query("SELECT name FROM " + schema + ".sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// sharedColumns returns the quoted column names table t has in both schemas.
func sharedColumns(q dbtx, t string) ([]string, error) {
	cols := func(schema string) (map[string]bool, []string, error) {
		rows, err := q.Query("PRAGMA " + schema + ".table_info(" + quoteIdent(t) + ")")
		if err != nil {
			return nil, nil, err
		}
		defer rows.Close()
		set := map[string]bool{}
		var order []string
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var dflt any
			if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return nil, nil, err
			}
			set[name] = true
			order = append(order, name)
		}
		return set, order, rows.Err()
	}
	_, mainOrder, err := cols("main")
	if err != nil {
		return nil, err
	}
	backupSet, _, err := cols("backup")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range mainOrder {
		if backupSet[c] {
			out = append(out, quoteIdent(c))
		}
	}
	return out, nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// danglingReferences reports host and stream references that do not resolve.
func danglingReferences(q dbtx) ([]string, error) {
	var out []string
	hosts, err := listHosts(q)
	if err != nil {
		return nil, err
	}
	for i := range hosts {
		if err := checkHostRefs(q, &hosts[i]); err != nil {
			out = append(out, hostLabel(hosts[i])+": "+err.Error())
		}
	}
	streams, err := listStreams(q)
	if err != nil {
		return nil, err
	}
	for i := range streams {
		if err := checkStreamRefs(q, &streams[i]); err != nil {
			out = append(out, fmt.Sprintf("stream :%d: %s", streams[i].ListenPort, err))
		}
	}
	return out, nil
}
