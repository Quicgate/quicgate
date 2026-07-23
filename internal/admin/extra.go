package admin

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pquerna/otp/totp"

	"quicgate/internal/engine"
	"quicgate/internal/store"
)

// ---- API tokens ----

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListAPITokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []store.APIToken{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	tok, err := s.store.CreateAPIToken(body.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, tok) // includes the raw token, shown once
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteAPIToken(id); err != nil {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---- 2FA (TOTP) ----

func (s *Server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: sess.email})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Return the secret + otpauth URI; not persisted until verified in enable.
	writeJSON(w, http.StatusOK, map[string]string{"secret": key.Secret(), "uri": key.URL()})
}

func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var body struct{ Secret, Code string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !totp.Validate(body.Code, body.Secret) {
		writeErr(w, http.StatusBadRequest, "code does not match; check your authenticator")
		return
	}
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetTOTPSecret(u.ID, body.Secret); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetTOTPSecret(u.ID, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// ---- access-log viewer ----

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
			n = parsed
		}
	}
	// host=<domain> keeps only that host's traffic; general=1 keeps only
	// traffic that does not belong to any configured host (scanners, raw-IP
	// hits) so the System page shows the noise and each host shows its own.
	wantHost := strings.ToLower(r.URL.Query().Get("host"))
	general := r.URL.Query().Get("general") == "1"
	var known map[string]bool
	if general {
		known = map[string]bool{}
		if hosts, err := s.store.ListHosts(); err == nil {
			for _, h := range hosts {
				for _, d := range h.Domains {
					known[strings.ToLower(d)] = true
				}
			}
		}
	}
	matches := func(line []byte) bool {
		if wantHost == "" && !general {
			return true
		}
		var e struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(line, &e) != nil {
			return false
		}
		h := strings.ToLower(e.Host)
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		if wantHost != "" {
			return h == wantHost
		}
		return !known[h]
	}
	f, err := os.Open(filepath.Join(s.dataDir, "logs", "access.log"))
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	defer f.Close()
	// Ring buffer of the last n matching JSON lines.
	ring := make([]json.RawMessage, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if !matches(sc.Bytes()) {
			continue
		}
		line := append([]byte(nil), sc.Bytes()...)
		if len(ring) < n {
			ring = append(ring, line)
		} else {
			copy(ring, ring[1:])
			ring[len(ring)-1] = line
		}
	}
	// Newest first.
	out := make([]json.RawMessage, 0, len(ring))
	for i := len(ring) - 1; i >= 0; i-- {
		out = append(out, ring[i])
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- effective config ----

func (s *Server) handleEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.EffectiveConfig()
	if cfg == nil {
		cfg = []engine.EffectiveRoute{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

// ---- self-signed + from-file certs ----

func (s *Server) handleSelfSignedCert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
		Days    int      `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, err := s.store.GenerateSelfSigned(body.Name, body.Domains, body.Days)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleCertFromFile(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name, CertPath, KeyPath string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, err := s.store.ImportCertFromFile(body.Name, body.CertPath, body.KeyPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// ---- declarative import ----

// handleImport creates hosts, access lists and streams from a JSON document,
// for GitOps-style config-as-code. Additive: existing entries are untouched.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var doc struct {
		AccessLists []store.AccessList `json:"accessLists"`
		Hosts       []store.Host       `json:"hosts"`
		Streams     []store.Stream     `json:"streams"`
	}
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	created := map[string]int{}
	for i := range doc.AccessLists {
		a := doc.AccessLists[i]
		a.ID = 0
		if err := s.store.CreateAccessList(&a); err != nil {
			writeErr(w, http.StatusBadRequest, "access list: "+err.Error())
			return
		}
		created["accessLists"]++
	}
	for i := range doc.Hosts {
		h := doc.Hosts[i]
		h.ID = 0
		if err := s.store.CreateHost(&h); err != nil {
			writeErr(w, http.StatusBadRequest, "host: "+err.Error())
			return
		}
		created["hosts"]++
	}
	for i := range doc.Streams {
		st := doc.Streams[i]
		st.ID = 0
		if err := s.store.CreateStream(&st, s.engine.ReservedPorts()); err != nil {
			writeErr(w, http.StatusBadRequest, "stream: "+err.Error())
			return
		}
		created["streams"]++
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, created)
}
