package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	dataDir  string
	mu       sync.Mutex
	sessions map[string]session
}

func New(st *store.Store, eng *engine.Engine, webFS fs.FS, dataDir string) *Server {
	return &Server{store: st, engine: eng, webFS: webFS, dataDir: dataDir, sessions: map[string]session{}}
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
	// LDAP admin login (additive)
	"ldap_enabled":          true,
	"ldap_url":              true,
	"ldap_bind_dn_template": true,
	// Docker label provider (default-domain is live; endpoints apply on restart)
	"docker_default_domain": true, // base domain for containers without quicgate.host
	"docker_endpoints":      true, // JSON list of Docker hosts to watch (restart to apply)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.AllSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for k := range settingsKeys {
		out[k] = all[k]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for k := range body {
		if !settingsKeys[k] {
			writeErr(w, http.StatusBadRequest, "unsupported setting: "+k)
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
		"version": info.Version,
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

func (s *Server) handleListStreams(w http.ResponseWriter, r *http.Request) {
	streams, err := s.store.ListStreams()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if streams == nil {
		streams = []store.Stream{}
	}
	writeJSON(w, http.StatusOK, streams)
}

// streamACLExists guards a stream's optional access-list source reference: a
// dangling id would silently drop to "no restriction", so reject it.
func (s *Server) streamACLExists(id *int64) error {
	if id == nil {
		return nil
	}
	lists, err := s.store.ListAccessLists()
	if err != nil {
		return err
	}
	for _, a := range lists {
		if a.ID == *id {
			return nil
		}
	}
	return errors.New("accessListId does not reference an existing access list")
}

func (s *Server) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var st store.Stream
	if err := decodeStrict(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.streamACLExists(st.AccessListID); err != nil {
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
	writeJSON(w, http.StatusCreated, st)
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
	if err := s.streamACLExists(st.AccessListID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
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
	writeJSON(w, http.StatusOK, st)
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email, Password, Code string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.store.GetUserByEmail(body.Email)
	localOK := err == nil && bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(body.Password)) == nil
	if !localOK {
		// Additive LDAP fallback; local admin always still works.
		if !s.ldapAuth(body.Email, body.Password) {
			time.Sleep(400 * time.Millisecond) // flat cost for wrong email and wrong password alike
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		u.Email = "ldap:" + body.Email // directory user, no local record
	}
	// Second factor, when enabled.
	if u.TOTPSecret != "" {
		if body.Code == "" {
			writeJSON(w, http.StatusOK, map[string]any{"totpRequired": true})
			return
		}
		if !totp.Validate(body.Code, u.TOTPSecret) {
			writeErr(w, http.StatusUnauthorized, "invalid authentication code")
			return
		}
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	id := hex.EncodeToString(tok)
	s.mu.Lock()
	s.sessions[id] = session{userID: u.ID, email: u.Email, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "qg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: isHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
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
