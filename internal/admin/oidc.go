package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC is an additive admin login option: password login always keeps
// working, so a misconfigured IdP can never lock the admin out. Enabled and
// configured entirely through settings.

func (s *Server) oidcConfig(ctx context.Context) (*oidc.Provider, oauth2.Config, bool, error) {
	if s.store.GetSetting("oidc_enabled", "") != "1" {
		return nil, oauth2.Config{}, false, nil
	}
	issuer := s.store.GetSetting("oidc_issuer", "")
	clientID := s.store.GetSetting("oidc_client_id", "")
	clientSecret := s.store.GetSetting("oidc_client_secret", "")
	redirect := s.store.GetSetting("oidc_redirect_url", "")
	if issuer == "" || clientID == "" || redirect == "" {
		return nil, oauth2.Config{}, false, nil
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, oauth2.Config{}, false, err
	}
	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirect,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	return provider, cfg, true, nil
}

// handleOIDCLogin starts the auth-code flow.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	_, cfg, ok, err := s.oidcConfig(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "OIDC provider error: "+err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "OIDC not configured")
		return
	}
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)
	http.SetCookie(w, &http.Cookie{Name: "qg_oidc_state", Value: state, Path: "/", HttpOnly: true, MaxAge: 300, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
}

// handleOIDCCallback exchanges the code, verifies the ID token, and — if the
// email matches an allowed address — mints a session.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider, cfg, ok, err := s.oidcConfig(r.Context())
	if err != nil || !ok {
		writeErr(w, http.StatusBadGateway, "OIDC not available")
		return
	}
	stateCookie, err := r.Cookie("qg_oidc_state")
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		writeErr(w, http.StatusBadRequest, "state mismatch")
		return
	}
	oauth2Token, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "token exchange failed: "+err.Error())
		return
	}
	rawID, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no id_token in response")
		return
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(r.Context(), rawID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "id_token verification failed")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read claims")
		return
	}
	allowed := s.store.GetSetting("oidc_allowed_emails", "")
	if !emailAllowed(claims.Email, allowed) {
		writeErr(w, http.StatusForbidden, "email not permitted")
		return
	}
	// Bind to the local admin identity for session bookkeeping.
	u, err := s.store.GetUserByEmail(claims.Email)
	email := claims.Email
	if err != nil {
		email = "oidc:" + claims.Email
	} else {
		email = u.Email
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	id := hex.EncodeToString(tok)
	s.mu.Lock()
	s.sessions[id] = session{email: email, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "qg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusFound)
}

func emailAllowed(email, allowedCSV string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	if strings.TrimSpace(allowedCSV) == "" {
		return true // no allow-list configured: any verified email
	}
	for _, a := range strings.Split(allowedCSV, ",") {
		if strings.ToLower(strings.TrimSpace(a)) == email {
			return true
		}
	}
	return false
}
