package admin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

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

// reauthenticate checks the account password again for a change to the
// account's own protection (second factor), so a borrowed or stolen session
// alone cannot switch it off or replace it.
func (s *Server) reauthenticate(sess session, password string) (store.User, int, string) {
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		return u, http.StatusBadRequest, "this account has no local password to confirm"
	}
	if password == "" || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
		return u, http.StatusUnauthorized, "confirm the change with your current password"
	}
	return u, 0, ""
}

func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var body struct{ Secret, Code, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, status, msg := s.reauthenticate(sess, body.Password)
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	if !totp.Validate(body.Code, body.Secret) {
		writeErr(w, http.StatusBadRequest, "code does not match; check your authenticator")
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
	var body struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, status, msg := s.reauthenticate(sess, body.Password)
	if status != 0 {
		writeErr(w, status, msg)
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
	br := bufio.NewReaderSize(f, 64*1024)
	for {
		raw, ok, err := nextLogLine(br, 1024*1024)
		if err != nil {
			break
		}
		if !ok || !matches(raw) {
			continue
		}
		line := append([]byte(nil), raw...)
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

// nextLogLine returns the next line of r without its line ending. A line
// longer than max is skipped whole (ok is false) rather than ending the read,
// so one oversized entry, which a client can cause with a long request path,
// cannot hide the entries after it. err is io.EOF at the end.
func nextLogLine(r *bufio.Reader, max int) (line []byte, ok bool, err error) {
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && (err != io.EOF || (len(line) == 0 && !tooLong)) {
			return nil, false, err
		}
		return bytes.TrimRight(line, "\r\n"), !tooLong, nil
	}
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

// handleImport applies a JSON document of access lists, hosts and streams, for
// GitOps-style config-as-code. It is all or nothing (one transaction; a
// rejected document changes neither the stored nor the running configuration)
// and repeatable (entries matching existing ones by name, domain set or listen
// port are updated in place). The response keeps the created counts at the top
// level, as before, and adds what was updated.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var doc store.ImportDoc
	if err := decodeStrict(r, &doc); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid document: "+err.Error())
		return
	}
	res, err := s.store.Import(doc, s.engine.ReservedPorts())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "import rejected, nothing was changed: "+err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "imported, but applying it failed: "+err.Error())
		return
	}
	out := map[string]any{"updated": res.Updated}
	for k, v := range res.Created {
		out[k] = v
	}
	for _, k := range []string{"accessLists", "hosts", "streams"} {
		if _, ok := out[k]; !ok {
			out[k] = 0
		}
	}
	writeJSON(w, http.StatusOK, out)
}
