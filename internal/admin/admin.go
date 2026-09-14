package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/docker"
	"quicgate/internal/engine"
	"quicgate/internal/store"
)

const sessionTTL = 12 * time.Hour

type session struct {
	userID  int64
	email   string
	expires time.Time
}

// Server is the management API + embedded UI, served on its own port.
type Server struct {
	store    *store.Store
	engine   *engine.Engine
	docker   *docker.Provider // nil unless the Docker label provider is enabled
	webFS    fs.FS
	logins   *loginThrottle
	dataDir  string
	mu       sync.Mutex
	sessions map[string]session
	// oidcLogins holds in-flight admin OIDC logins by state, each usable once.
	oidcLogins map[string]adminOIDCLogin
}

func New(st *store.Store, eng *engine.Engine, webFS fs.FS, dataDir string) *Server {
	return &Server{store: st, engine: eng, webFS: webFS, dataDir: dataDir, sessions: map[string]session{},
		oidcLogins: map[string]adminOIDCLogin{}, logins: newLoginThrottle()}
}

// SetDocker attaches the Docker label provider so the API can report its status
// and adopt derived routes. Called before Handler().
func (s *Server) SetDocker(p *docker.Provider) { s.docker = p }

// EnsureAdmin seeds the NPM-style default admin on first run.
func (s *Server) EnsureAdmin() error {
	n, err := s.store.CountUsers()
	if err != nil || n > 0 {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.store.CreateUser("admin@example.com", string(hash), true); err != nil {
		return err
	}
	log.Printf("admin: created default user admin@example.com / changeme (password change is forced on first login)")
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /api/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("GET /api/auth-methods", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{
			"oidc": s.store.GetSetting("oidc_enabled", "") == "1",
			"ldap": s.ldapConfigured(),
		})
	})
	// Unauthenticated so update-checkers / uptime monitors can read it; the
	// version is public on GitHub anyway and reveals nothing sensitive.
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": s.engine.Version(), "go": runtime.Version()})
	})
	mux.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	mux.HandleFunc("GET /api/me", s.auth(s.handleMe))
	mux.HandleFunc("POST /api/password", s.auth(s.handlePassword))
	mux.HandleFunc("POST /api/sessions/revoke", s.auth(s.handleRevokeSessions))
	mux.HandleFunc("POST /api/sso/revoke-sessions", s.auth(s.handleRevokeSSOSessions))
	mux.HandleFunc("GET /api/hosts", s.auth(s.handleListHosts))
	mux.HandleFunc("POST /api/hosts", s.auth(s.handleCreateHost))
	mux.HandleFunc("PUT /api/hosts/{id}", s.auth(s.handleUpdateHost))
	mux.HandleFunc("DELETE /api/hosts/{id}", s.auth(s.handleDeleteHost))
	mux.HandleFunc("GET /api/certs", s.auth(s.handleCerts))
	mux.HandleFunc("GET /api/health", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.engine.HealthStatuses())
	}))
	mux.HandleFunc("GET /api/custom-certs", s.auth(s.handleListCustomCerts))
	mux.HandleFunc("POST /api/custom-certs", s.auth(s.handleCreateCustomCert))
	mux.HandleFunc("PUT /api/custom-certs/{id}", s.auth(s.handleUpdateCustomCert))
	mux.HandleFunc("DELETE /api/custom-certs/{id}", s.auth(s.handleDeleteCustomCert))
	mux.HandleFunc("GET /api/access-lists", s.auth(s.handleListAccessLists))
	mux.HandleFunc("POST /api/access-lists", s.auth(s.handleCreateAccessList))
	mux.HandleFunc("PUT /api/access-lists/{id}", s.auth(s.handleUpdateAccessList))
	mux.HandleFunc("DELETE /api/access-lists/{id}", s.auth(s.handleDeleteAccessList))
	mux.HandleFunc("GET /api/oidc-providers", s.auth(s.handleListOIDCProviders))
	mux.HandleFunc("POST /api/oidc-providers", s.auth(s.handleCreateOIDCProvider))
	mux.HandleFunc("PUT /api/oidc-providers/{id}", s.auth(s.handleUpdateOIDCProvider))
	mux.HandleFunc("DELETE /api/oidc-providers/{id}", s.auth(s.handleDeleteOIDCProvider))
	mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.auth(s.handlePutSettings))
	mux.HandleFunc("GET /api/backup", s.auth(s.handleBackup))
	mux.HandleFunc("POST /api/restore", s.auth(s.handleRestore))
	mux.HandleFunc("POST /api/notify-test", s.auth(func(w http.ResponseWriter, r *http.Request) {
		s.engine.NotifyTest()
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
	}))
	mux.HandleFunc("GET /api/streams", s.auth(s.handleListStreams))
	mux.HandleFunc("POST /api/streams", s.auth(s.handleCreateStream))
	mux.HandleFunc("PUT /api/streams/{id}", s.auth(s.handleUpdateStream))
	mux.HandleFunc("DELETE /api/streams/{id}", s.auth(s.handleDeleteStream))
	mux.HandleFunc("GET /api/port-forwards", s.auth(s.handleListPortForwards))
	mux.HandleFunc("POST /api/port-forwards", s.auth(s.handleCreatePortForward))
	mux.HandleFunc("PUT /api/port-forwards/{id}", s.auth(s.handleUpdatePortForward))
	mux.HandleFunc("DELETE /api/port-forwards/{id}", s.auth(s.handleDeletePortForward))
	mux.HandleFunc("GET /api/tokens", s.auth(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", s.auth(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.auth(s.handleDeleteToken))
	mux.HandleFunc("POST /api/2fa/setup", s.auth(s.handle2FASetup))
	mux.HandleFunc("POST /api/2fa/enable", s.auth(s.handle2FAEnable))
	mux.HandleFunc("POST /api/2fa/disable", s.auth(s.handle2FADisable))
	mux.HandleFunc("GET /api/logs", s.auth(s.handleLogs))
	mux.HandleFunc("GET /api/config", s.auth(s.handleEffectiveConfig))
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/traffic", s.auth(s.handleTraffic))
	mux.HandleFunc("POST /api/import", s.auth(s.handleImport))
	mux.HandleFunc("POST /api/custom-certs/self-signed", s.auth(s.handleSelfSignedCert))
	mux.HandleFunc("POST /api/custom-certs/from-file", s.auth(s.handleCertFromFile))
	mux.HandleFunc("GET /api/docker/status", s.auth(s.handleDockerStatus))
	mux.HandleFunc("POST /api/docker/adopt", s.auth(s.handleDockerAdopt))
	mux.HandleFunc("GET /api/geoip/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.engine.GeoIPStatus())
	}))
	mux.HandleFunc("POST /api/geoip/reload", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.engine.GeoIPReload())
	}))
	mux.HandleFunc("GET /api/geoip/lookup", s.auth(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.engine.GeoLookup(r.URL.Query().Get("ip"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"country": c})
	}))
	mux.HandleFunc("GET /metrics", s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(s.engine.MetricsText()))
	}))
	mux.Handle("/", http.FileServerFS(s.webFS))
	return s.securityHeaders(s.csrf(mux))
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

// settingsKeys is the closed set of UI-editable settings; unknown keys are
// rejected, in keeping with the no-silent-drop contract.
var settingsKeys = map[string]bool{
	"acme_staging":       true, // "1" = Let's Encrypt staging CA
	"acme_email":         true,
	"notify_url":         true, // webhook (ntfy/Gotify style) for failure alerts
	"default_site":       true, // 404 | html | redirect for unmatched hosts
	"default_site_value": true, // custom HTML or redirect URL
	"acme_dns_provider":  true, // "" | transip  (DNS-01 for wildcards)
	"acme_dns_config":    true, // provider credentials (JSON)
	"acme_ca_url":        true, // custom ACME directory (ZeroSSL/step-ca)
	"ban_enabled":        true, // "1" = auto-ban on repeated auth failures
	"ban_threshold":      true,
	"ban_window_sec":     true,
	"ban_duration_sec":   true,
	// OIDC admin login (additive; password always works)
	"oidc_enabled":        true,
	"oidc_issuer":         true,
	"oidc_client_id":      true,
	"oidc_client_secret":  true,
	"oidc_redirect_url":   true,
	"oidc_allowed_emails": true,
	// Reuse a provider from the Identity providers list instead of repeating
	// issuer/client id/secret here; the inline fields remain the fallback.
	"admin_oidc_provider_id": true,
	// LDAP admin login (additive)
	"ldap_enabled":          true,
	"ldap_url":              true,
	"ldap_bind_dn_template": true,
	"ldap_allowed_users":    true, // directory users permitted to administer quicgate
	// Docker label provider (default-domain is live; endpoints apply on restart)
	"docker_default_domain": true, // base domain for containers without quicgate.host
	"docker_endpoints":      true, // JSON list of Docker hosts to watch (restart to apply)
	// Real client IP when behind a trusted proxy (Cloudflare / another LB)
	"trusted_proxies": true, // CIDRs allowed to set the real-IP header
	"real_ip_header":  true, // header carrying the real client IP (e.g. X-Forwarded-For)
}

// secretSettings are never echoed back in cleartext. They are credentials for
// other systems (an IdP client secret, a DNS provider's API key), so returning
// them on every settings read puts them in the browser, in devtools and in any
// HAR or screenshot the user shares. The UI sends the mask back unchanged when
// the field was not edited, which handlePutSettings treats as "keep".
var secretSettings = map[string]bool{
	"oidc_client_secret": true,
	"acme_dns_config":    true,
}

const secretMask = "********"

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.AllSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for k := range settingsKeys {
		v := all[k]
		if secretSettings[k] && v != "" {
			v = secretMask
		}
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for k, v := range body {
		if secretSettings[k] && v == secretMask {
			delete(body, k) // unchanged in the UI: keep what is stored
			continue
		}
		if !settingsKeys[k] {
			writeErr(w, http.StatusBadRequest, "unsupported setting: "+k)
			return
		}
	}
	// The admin sign-in provider is a reference like any other: it must resolve.
	if id, ok := body["admin_oidc_provider_id"]; ok && id != "" {
		if _, found, err := s.adminOIDCProvider(id); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		} else if !found {
			writeErr(w, http.StatusBadRequest, "identity provider "+id+" does not exist")
			return
		}
	}
	for k, v := range body {
		if err := s.store.SetSetting(k, v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	// A changed Docker tunable (connect-mode, host address, default domain) only
	// takes effect on the next reconcile; poke the provider so it is immediate.
	if s.docker != nil {
		for k := range body {
			if strings.HasPrefix(k, "docker_") {
				s.docker.Trigger()
				break
			}
		}
	}
	s.handleGetSettings(w, r)
}

// handleOverview aggregates a lightweight at-a-glance snapshot for the
// dashboard: listeners, config counts, upstream/cert health, feature flags, and
// providers. One call so the dashboard is a single fetch.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.store.ListHosts()
	byType := map[string]int{}
	enabled, fwdAuth, withACL := 0, 0, 0
	for _, h := range hosts {
		byType[h.Type]++
		if h.Enabled {
			enabled++
		}
		if h.Options.ForwardAuth != nil && h.Options.ForwardAuth.URL != "" {
			fwdAuth++
		}
		if h.AccessListID != nil {
			withACL++
		}
	}
	certs := map[string]int{"issued": 0, "pending": 0, "failed": 0}
	for _, c := range s.engine.CertStatuses(r.Context()) {
		certs[c.Status]++
	}
	streams, _ := s.store.ListStreams()
	streamsOn := 0
	for _, st := range streams {
		if st.Enabled {
			streamsOn++
		}
	}
	lists, _ := s.store.ListAccessLists()
	up, down := 0, 0
	for _, t := range s.engine.HealthStatuses() {
		if t.Up {
			up++
		} else {
			down++
		}
	}
	info := s.engine.Info()

	out := map[string]any{
		"version":   info.Version,
		"startedAt": info.StartedAt,
		"listeners": map[string]any{
			"http": info.HTTPAddr, "https": info.HTTPSAddr, "tls": info.TLS, "http3": info.HTTP3,
		},
		"hosts": map[string]any{
			"total": len(hosts), "enabled": enabled, "byType": byType,
			"withAccessList": withACL, "forwardAuth": fwdAuth,
		},
		"certs":       certs,
		"streams":     map[string]int{"total": len(streams), "enabled": streamsOn},
		"accessLists": len(lists),
		"upstreams":   map[string]int{"up": up, "down": down},
		"features": map[string]bool{
			"http3":       info.HTTP3,
			"upnp":        info.UPnP,
			"autoban":     s.store.GetSetting("ban_enabled", "") == "1",
			"geoip":       s.engine.GeoIPStatus().Loaded,
			"oidc":        s.store.GetSetting("oidc_enabled", "") == "1",
			"ldap":        s.ldapConfigured(),
			"forwardAuth": fwdAuth > 0,
			"docker":      s.docker != nil,
		},
	}
	if s.docker != nil {
		st := s.docker.Status()
		epUp, routed := 0, 0
		for _, e := range st.Endpoints {
			if e.Connected {
				epUp++
			}
		}
		for _, c := range st.Containers {
			if c.Routed {
				routed++
			}
		}
		out["docker"] = map[string]any{
			"endpoints": len(st.Endpoints), "connected": epUp,
			"containers": len(st.Containers), "routed": routed,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleTraffic serves the traffic history behind the overview charts for one
// range (1h by default).
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "1h"
	}
	rep, err := s.engine.TrafficReport(rng)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleDockerStatus reports the Docker label provider's live state, or that it
// is disabled when the provider is not running.
func (s *Server) handleDockerStatus(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.docker.Status())
}

// handleDockerAdopt persists the host and streams derived for one container as
// editable configuration. The manual-wins rule then makes the provider drop its
// derived version on the next reconcile, so nothing is ever served twice.
func (s *Server) handleDockerAdopt(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeErr(w, http.StatusBadRequest, "docker integration is not enabled")
		return
	}
	var body struct {
		Endpoint string `json:"endpoint"`
		Name     string `json:"name"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host, streams, ok := s.docker.Adopt(body.Endpoint, body.Name)
	if !ok {
		writeErr(w, http.StatusNotFound, "no routable container named "+body.Name)
		return
	}
	if host != nil {
		if err := s.store.CreateHost(host); err != nil {
			writeErr(w, http.StatusBadRequest, "create host: "+err.Error())
			return
		}
	}
	reserved := s.engine.ReservedPorts()
	for i := range streams {
		if err := s.store.CreateStream(&streams[i], reserved); err != nil {
			writeErr(w, http.StatusBadRequest, "create stream: "+err.Error())
			return
		}
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "adopted, but applying it failed: "+err.Error())
		return
	}
	s.docker.Trigger() // re-derive so the container immediately shows as managed
	writeJSON(w, http.StatusCreated, map[string]any{"host": host, "streams": streams})
}

func (s *Server) handleListAccessLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListAccessLists()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if lists == nil {
		lists = []store.AccessList{}
	}
	writeJSON(w, http.StatusOK, lists)
}

func (s *Server) handleCreateAccessList(w http.ResponseWriter, r *http.Request) {
	var a store.AccessList
	if err := decodeStrict(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateAccessList(&a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleUpdateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var a store.AccessList
	if err := decodeStrict(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.ID = id
	if err := s.store.UpdateAccessList(&a); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "access list not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleDeleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteAccessList(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "access list not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// streamView is a stored stream plus the state of its listeners, so saving a
// stream never reads as "running" when the engine could not start it (a port
// another process holds, a missing certificate, no trusted PROXY peer).
type streamView struct {
	store.Stream
	Listeners []engine.StreamStatus `json:"listeners"`
}

func (s *Server) streamViews(streams []store.Stream) []streamView {
	byID := map[int64][]engine.StreamStatus{}
	for _, st := range s.engine.StreamStatuses() {
		byID[st.StreamID] = append(byID[st.StreamID], st)
	}
	out := make([]streamView, 0, len(streams))
	for _, st := range streams {
		ls := byID[st.ID]
		if ls == nil {
			ls = []engine.StreamStatus{}
		}
		out = append(out, streamView{Stream: st, Listeners: ls})
	}
	return out
}

func (s *Server) handleListStreams(w http.ResponseWriter, r *http.Request) {
	streams, err := s.store.ListStreams()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.streamViews(streams))
}

func (s *Server) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var st store.Stream
	if err := decodeStrict(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateStream(&st, s.engine.ReservedPorts()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.streamViews([]store.Stream{st})[0])
}

func (s *Server) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var st store.Stream
	if err := decodeStrict(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	st.ID = id
	if err := s.store.UpdateStream(&st, s.engine.ReservedPorts()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "stream not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.streamViews([]store.Stream{st})[0])
}

func (s *Server) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteStream(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "stream not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListPortForwards(w http.ResponseWriter, r *http.Request) {
	pfs, err := s.store.ListPortForwards()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pfs == nil {
		pfs = []store.PortForward{}
	}
	writeJSON(w, http.StatusOK, pfs)
}

func (s *Server) handleCreatePortForward(w http.ResponseWriter, r *http.Request) {
	var p store.PortForward
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreatePortForward(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdatePortForward(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p store.PortForward
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID = id
	if err := s.store.UpdatePortForward(&p); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "port forward not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeletePortForward(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeletePortForward(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "port forward not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type ctxKey int

const sessionKey ctxKey = 0

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie("qg_session"); err == nil {
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "cross-site request blocked")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// API-token bearer auth for automation (no session/2FA needed).
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			if s.store.ValidAPIToken(strings.TrimPrefix(h, "Bearer ")) {
				next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, session{email: "api-token"})))
				return
			}
			writeErr(w, http.StatusUnauthorized, "invalid API token")
			return
		}
		c, err := r.Cookie("qg_session")
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		s.mu.Lock()
		sess, ok := s.sessions[c.Value]
		if ok && time.Now().After(sess.expires) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		if s.passwordChangeRequired(sess, r) {
			writeErr(w, http.StatusForbidden, "password change required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	}
}

// isExternalIdentity reports whether a session belongs to a directory or IdP
// user with no local account, which the login handlers mark with a prefix.
func isExternalIdentity(email string) bool {
	return strings.HasPrefix(email, "oidc:") || strings.HasPrefix(email, "ldap:")
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) passwordChangeRequired(sess session, r *http.Request) bool {
	if sess.email == "api-token" || sess.userID == 0 {
		return false
	}
	if r.URL.Path == "/api/password" || r.URL.Path == "/api/logout" || r.URL.Path == "/api/me" {
		return false
	}
	u, err := s.store.GetUserByEmail(sess.email)
	return err == nil && u.MustChange
}

// testHookLoginVerified, when a test sets it, runs after a login's credentials
// are verified and before its session is created.
var testHookLoginVerified func()

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.logins.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}
	var body struct{ Email, Password, Code string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.store.GetUserByEmail(body.Email)
	localOK := err == nil && bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(body.Password)) == nil
	if !localOK {
		// Additive LDAP fallback; local admin always still works.
		// Binding proves the directory knows the password; being allowed to
		// administer the proxy is a separate decision.
		if !s.ldapAuth(body.Email, body.Password) || !s.ldapIdentityApproved(body.Email) {
			s.logins.fail(ip)
			time.Sleep(400 * time.Millisecond) // flat cost for wrong email and wrong password alike
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if u.Email == "" {
			u.Email = "ldap:" + body.Email // directory user, no local record
		}
	}
	// Second factor, when enabled.
	if u.TOTPSecret != "" {
		if body.Code == "" {
			writeJSON(w, http.StatusOK, map[string]any{"totpRequired": true})
			return
		}
		if !totp.Validate(body.Code, u.TOTPSecret) {
			// Counted like a wrong password: six digits are guessable fast.
			s.logins.fail(ip)
			writeErr(w, http.StatusUnauthorized, "invalid authentication code")
			return
		}
	}
	if testHookLoginVerified != nil {
		testHookLoginVerified()
	}
	start := s.startSession
	if localOK {
		start = s.startSessionIfUnchanged(u)
	}
	if err := start(w, r, u.ID, u.Email); errors.Is(err, errCredentialsChanged) {
		writeErr(w, http.StatusUnauthorized, "the account's credentials changed while signing in, sign in again")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logins.succeed(ip)
	writeJSON(w, http.StatusOK, map[string]any{"email": u.Email, "mustChange": u.MustChange, "version": s.engine.Version()})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("qg_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "qg_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r), MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		// An allow-listed OIDC/LDAP identity has no local row; the directory
		// owns the credential, so report the session identity and no local 2FA
		// rather than failing the profile call.
		if isExternalIdentity(sess.email) {
			writeJSON(w, http.StatusOK, map[string]any{
				"email": sess.email, "mustChange": false, "totpEnabled": false,
				"external": true, "version": s.engine.Version(),
			})
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": u.Email, "mustChange": u.MustChange, "totpEnabled": u.TOTPSecret != "", "version": s.engine.Version()})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var body struct{ Current, New string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(body.New) < 8 {
		writeErr(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(body.Current)) != nil {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetPassword(u.ID, string(hash)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Whoever held the old password may hold a session too: end every session
	// of this account, and give the caller a fresh one.
	s.revokeSessions(sameIdentity(sess), "")
	if err := s.startSession(w, r, sess.userID, sess.email); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []store.Host{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var h store.Host
	if err := decodeStrict(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateHost(&h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var h store.Host
	if err := decodeStrict(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.ID = id
	if err := s.store.UpdateHost(&h); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteHost(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	statuses := s.engine.CertStatuses(r.Context())
	if statuses == nil {
		statuses = []engine.CertStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func (s *Server) handleListCustomCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.ListCustomCerts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if certs == nil {
		certs = []store.CustomCert{}
	}
	writeJSON(w, http.StatusOK, certs)
}

func (s *Server) handleCreateCustomCert(w http.ResponseWriter, r *http.Request) {
	var c store.CustomCert
	if err := decodeStrict(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateCustomCert(&c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleUpdateCustomCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var c store.CustomCert
	if err := decodeStrict(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateCustomCertPEM(id, &c); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "certificate not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDeleteCustomCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteCustomCert(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "certificate not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// reload applies the stored config to the engine. A change that saves but
// fails to apply must be loud: a silent failure leaves the engine serving a
// stale config until the next reload, which reads as "needs a restart".
func (s *Server) reload(ctx context.Context) error {
	err := s.engine.Reload(ctx)
	if err != nil {
		log.Printf("admin: reload failed, retrying once: %v", err)
		err = s.engine.Reload(ctx)
	}
	if err != nil {
		log.Printf("admin: reload after change failed: %v", err)
	}
	return err
}

// decodeStrict rejects unknown fields so a typo'd or removed option can never
// be silently dropped, which is the whole contract of structured options.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return errors.New("unsupported option: " + err.Error())
		}
		return err
	}
	return nil
}
