package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

// Admin sessions live in memory. Anything that changes who may administer the
// proxy (a password change, a restore, an explicit sign-out of every session)
// revokes the affected sessions at once rather than letting them run out their
// 12 hours.

// newSessionID returns a fresh random session id.
func newSessionID() (string, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return "", errors.New("entropy failure")
	}
	return hex.EncodeToString(tok), nil
}

// startSession stores a session for the identity and sets its cookie.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64, email string) error {
	id, err := newSessionID()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions[id] = session{userID: userID, email: email, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "qg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: isHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
	return nil
}

// revokeSessions deletes every session match accepts, except the one with id
// keep (empty keeps none). It returns how many were revoked.
func (s *Server) revokeSessions(match func(session) bool, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if id != keep && match(sess) {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// sameIdentity matches every session of the account behind sess.
func sameIdentity(sess session) func(session) bool {
	return func(o session) bool {
		if sess.userID != 0 {
			return o.userID == sess.userID
		}
		return o.email == sess.email
	}
}

// handleRevokeSessions signs out every other admin session: the caller's own
// session stays (an API token caller has none, so all are revoked).
func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	keep := ""
	if c, err := r.Cookie("qg_session"); err == nil {
		keep = c.Value
	}
	n := s.revokeSessions(func(session) bool { return true }, keep)
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// handleRevokeSSOSessions rotates the signing key of the built-in SSO session
// cookies, which signs every user out of every SSO-protected host at once.
func (s *Server) handleRevokeSSOSessions(w http.ResponseWriter, r *http.Request) {
	if err := s.store.SetSetting("sso_cookie_secret", ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "key cleared, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}
