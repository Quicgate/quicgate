package admin

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"quicgate/internal/engine"
	"quicgate/internal/store"
)

// ---- what a limited API token may reach ----

// monitorRoutes is everything a monitoring token may call, by the pattern the
// route is registered under. It is a list of what is allowed, not of what is
// refused: a route added later is closed to limited tokens until someone
// decides it belongs here. None of these answers carries a secret or a host's
// configuration (a host's header rules can hold a backend's credentials,
// which is why the plain host list is not on it).
var monitorRoutes = map[string]bool{
	"GET /api/me":           true,
	"GET /api/overview":     true,
	"GET /api/hosts/status": true,
	"GET /api/health":       true,
	"GET /api/certs":        true,
	"GET /api/traffic":      true,
	"GET /api/bans":         true,
	"GET /metrics":          true,
}

// switchRoutes is what a switch token may call on top of monitorRoutes.
var switchRoutes = map[string]bool{
	"PUT /api/hosts/{id}/enabled": true,
}

// tokenMay reports whether a token of this access level may call the route
// registered under pattern. An unknown level may do nothing.
func tokenMay(access, pattern string) bool {
	switch access {
	case store.TokenFull:
		return true
	case store.TokenSwitch:
		return monitorRoutes[pattern] || switchRoutes[pattern]
	case store.TokenMonitor:
		return monitorRoutes[pattern]
	}
	return false
}

// tokenAccessName is an access level in the words the interface uses.
func tokenAccessName(access string) string {
	switch access {
	case store.TokenMonitor:
		return "monitoring"
	case store.TokenSwitch:
		return "monitoring and host switch"
	}
	return "full access"
}

// ---- host status ----

// hostStatus is one host as a status page wants it: what it is, whether it is
// on, whether its backends answer and how its certificate is doing. It leaves
// out everything a host is configured with.
type hostStatus struct {
	ID       int64                 `json:"id"`
	Name     string                `json:"name"` // the first domain
	Domains  []string              `json:"domains"`
	Type     string                `json:"type"`
	Enabled  bool                  `json:"enabled"`
	Target   string                `json:"target,omitempty"`
	Backends []engine.TargetStatus `json:"backends"`
	// Certificate is absent for a host without one, and for a host that is
	// off: quicgate holds no certificate for a name it does not serve.
	Certificate *hostCertStatus `json:"certificate,omitempty"`
}

// hostCertStatus sums up the certificates of a host's domains: the worst
// state among them, and for issued ones the date the first of them expires.
type hostCertStatus struct {
	Mode      string `json:"mode"`   // auto | custom
	Status    string `json:"status"` // issued | pending | failed
	Domain    string `json:"domain,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

func hostTarget(h store.Host) string {
	switch h.Type {
	case "proxy":
		if h.Upstream.Host == "" {
			return ""
		}
		t := fmt.Sprintf("%s://%s:%d", h.Upstream.Scheme, h.Upstream.Host, h.Upstream.Port)
		if len(h.Upstreams) > 0 {
			t += fmt.Sprintf(" (+%d pool)", len(h.Upstreams))
		}
		return t
	case "redirect":
		if h.Redirect != nil {
			return fmt.Sprintf("%d -> %s", h.Redirect.HTTPCode, h.Redirect.TargetHost)
		}
	case "static":
		return "static files"
	}
	return ""
}

// certRank orders certificate states from fine to worst.
func certRank(status string) int {
	switch status {
	case "failed":
		return 2
	case "pending":
		return 1
	}
	return 0
}

func (s *Server) handleHostStatus(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	managed := map[string]engine.CertStatus{}
	for _, c := range s.engine.CertStatuses(r.Context()) {
		managed[c.Domain] = c
	}
	custom := map[int64]store.CustomCert{}
	if certs, err := s.store.ListCustomCerts(); err == nil {
		for _, c := range certs {
			custom[c.ID] = c
		}
	}
	out := make([]hostStatus, 0, len(hosts))
	for _, h := range hosts {
		st := hostStatus{ID: h.ID, Domains: h.Domains, Type: h.Type, Enabled: h.Enabled, Target: hostTarget(h), Backends: s.engine.BackendStatuses(h)}
		if len(h.Domains) > 0 {
			st.Name = h.Domains[0]
		}
		switch {
		case !h.Enabled:
		case h.CertMode == "auto":
			for _, d := range h.Domains {
				c, ok := managed[d]
				if !ok {
					continue
				}
				cur := st.Certificate
				worse := cur == nil || certRank(c.Status) > certRank(cur.Status)
				sooner := cur != nil && c.Status == "issued" && cur.Status == "issued" && c.NotAfter < cur.NotAfter
				if worse || sooner {
					st.Certificate = &hostCertStatus{Mode: "auto", Status: c.Status, Domain: c.Domain, NotAfter: c.NotAfter, LastError: c.LastError}
				}
			}
		case h.CertMode == "custom" && h.CertID != nil:
			if c, ok := custom[*h.CertID]; ok {
				st.Certificate = &hostCertStatus{Mode: "custom", Status: "issued", NotAfter: c.NotAfter}
			}
		}
		out = append(out, st)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetHostEnabled switches one host on or off, and nothing else.
func (s *Server) handleSetHostEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeBodyErr(w, err)
		return
	}
	if body.Enabled == nil {
		writeErr(w, http.StatusBadRequest, `say what you want: {"enabled": true} or {"enabled": false}`)
		return
	}
	if err := s.store.SetHostEnabled(id, *body.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := "off"
	if *body.Enabled {
		state = "on"
	}
	log.Printf("admin: host %d switched %s", id, state)
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": *body.Enabled})
}
