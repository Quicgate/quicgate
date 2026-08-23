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
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read claims")
		return
	}
	// An address the provider itself will not vouch for must not become an
	// admin login: on IdPs where users can set their own, anyone could claim
	// the address of a real administrator.
	if claims.Verified != nil && !*claims.Verified {
		writeErr(w, http.StatusForbidden, "identity provider reports this address as unverified")
		return
	}
	// Who gets in: an existing local admin with the same address, or an
	// address named explicitly in the allow-list. An empty allow-list used to
	// mean "anybody this IdP will authenticate", which hands the whole proxy
	// to every account in someone else's tenant.
	u, localErr := s.store.GetUserByEmail(claims.Email)
	allowList := s.store.GetSetting("oidc_allowed_emails", "")
	if localErr != nil && !emailAllowed(claims.Email, allowList) {
		writeErr(w, http.StatusForbidden, "email not permitted")
		return
	}
	// Keep the local identity when there is one, so sessions, the forced
	// password change and the profile page all resolve to the real account.
	email := "oidc:" + strings.ToLower(strings.TrimSpace(claims.Email))
	if localErr == nil {
		email = u.Email
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	id := hex.EncodeToString(tok)
	s.mu.Lock()
	s.sessions[id] = session{userID: u.ID, email: email, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "qg_session", Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// emailAllowed reports whether an external address is named in an allow-list.
// An empty list matches nothing: callers pair it with a local-account check,
// so "not configured" fails closed instead of admitting the whole directory.
func emailAllowed(email, allowedCSV string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	for _, a := range strings.Split(allowedCSV, ",") {
		if strings.ToLower(strings.TrimSpace(a)) == email {
			return true
		}
	}
	return false
}
