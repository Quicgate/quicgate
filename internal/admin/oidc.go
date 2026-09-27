package admin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"quicgate/internal/store"
)

// OIDC is an additive admin login option: password login always keeps
// working, so a misconfigured IdP can never lock the admin out. Enabled and
// configured entirely through settings: the switch plus inline issuer, client
// and redirect URL, or simply a provider selected from the Identity providers
// list, with the redirect URL derived from the request when none is set.

const (
	// adminOIDCLoginTTL is how long a started sign-in may take at the IdP.
	adminOIDCLoginTTL = 5 * time.Minute
	// oidcHTTPTimeout bounds every request to the IdP: discovery, the token
	// exchange and the key set.
	oidcHTTPTimeout = 15 * time.Second
	// oidcDiscoveryTTL is how long a discovered provider configuration is
	// reused before it is fetched again.
	oidcDiscoveryTTL = time.Hour
)

// adminOIDCMaxPending bounds in-flight sign-ins held in memory. At the cap a
// new sign-in is refused, never a live one dropped: whoever is in the middle
// of signing in must be able to finish. A variable so tests can use a small
// table.
var adminOIDCMaxPending = 1024

// adminOIDCLogin is one in-flight admin sign-in. It is created by the login
// redirect and consumed by the first callback that presents its state, so a
// callback URL cannot be replayed, and it carries the PKCE verifier and the
// nonce the ID token must echo, which bind the returned code and token to the
// browser that started the sign-in.
type adminOIDCLogin struct {
	nonce    string
	verifier string
	expires  time.Time
}

// discoveredProvider is a cached result of OIDC discovery for one issuer.
type discoveredProvider struct {
	provider *oidc.Provider
	expires  time.Time
}

func oidcClientContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, &http.Client{Timeout: oidcHTTPTimeout})
}

// adminOIDCProvider resolves the admin_oidc_provider_id setting value.
func (s *Server) adminOIDCProvider(id string) (store.OIDCProvider, bool, error) {
	list, err := s.store.ListOIDCProviders()
	if err != nil {
		return store.OIDCProvider{}, false, err
	}
	for _, p := range list {
		if strconv.FormatInt(p.ID, 10) == id {
			return p, true, nil
		}
	}
	return store.OIDCProvider{}, false, nil
}

// oidcEnabled reports whether admin sign-in through an identity provider is
// on: the switch, or a provider selected from the list. Selecting one is the
// whole configuration; it would be a surprise for the login to answer "not
// configured" after that.
func (s *Server) oidcEnabled() bool {
	return s.store.GetSetting("oidc_enabled", "") == "1" || s.store.GetSetting("admin_oidc_provider_id", "") != ""
}

// discover returns the issuer's discovered configuration, fetched at most
// once per oidcDiscoveryTTL: discovery is a request to the IdP, and the login
// endpoint that needs it is unauthenticated. The provider fetches the key set
// later, on the callback's verify, with the context it was made with, so it
// gets one that outlives the request that made it.
func (s *Server) discover(issuer string) (*oidc.Provider, error) {
	s.oidcMu.Lock()
	d, ok := s.oidcDiscovery[issuer]
	s.oidcMu.Unlock()
	if ok && time.Now().Before(d.expires) {
		return d.provider, nil
	}
	p, err := oidc.NewProvider(oidcClientContext(context.Background()), issuer)
	if err != nil {
		return nil, err
	}
	s.oidcMu.Lock()
	s.oidcDiscovery[issuer] = discoveredProvider{provider: p, expires: time.Now().Add(oidcDiscoveryTTL)}
	s.oidcMu.Unlock()
	return p, nil
}

func (s *Server) oidcConfig(r *http.Request) (*oidc.Provider, oauth2.Config, bool, error) {
	if !s.oidcEnabled() {
		return nil, oauth2.Config{}, false, nil
	}
	issuer := s.store.GetSetting("oidc_issuer", "")
	clientID := s.store.GetSetting("oidc_client_id", "")
	clientSecret := s.store.GetSetting("oidc_client_secret", "")
	scopes := []string{oidc.ScopeOpenID, "email", "profile"}
	// The admin plane can reuse an identity provider defined for proxied hosts
	// instead of repeating issuer/client here. Give it its own client on the
	// IdP even so: the control plane deserves a separate audience from the
	// applications behind it. The inline fields stay as the fallback, so
	// existing configurations keep working untouched.
	if id := s.store.GetSetting("admin_oidc_provider_id", ""); id != "" {
		p, found, err := s.adminOIDCProvider(id)
		if err != nil {
			return nil, oauth2.Config{}, false, err
		}
		if !found {
			// Never fall back to the inline issuer: that is a different sign-in
			// than the one the operator selected.
			return nil, oauth2.Config{}, false, fmt.Errorf("the selected identity provider %s no longer exists", id)
		}
		issuer, clientID, clientSecret = p.Issuer, p.ClientID, p.ClientSecret
		if len(p.Scopes) > 0 {
			scopes = p.Scopes
		}
	}
	redirect := s.store.GetSetting("oidc_redirect_url", "")
	if redirect == "" && r.Host != "" {
		// Not set: this listener's own callback, at the name and scheme the
		// browser used. The IdP checks it against what was registered there,
		// so a wrong guess fails loudly at the IdP; the explicit setting
		// remains for deployments where the guess is wrong.
		redirect = s.requestScheme(r) + "://" + r.Host + "/api/oidc/callback"
	}
	if issuer == "" || clientID == "" || redirect == "" {
		return nil, oauth2.Config{}, false, nil
	}
	provider, err := s.discover(issuer)
	if err != nil {
		return nil, oauth2.Config{}, false, err
	}
	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirect,
		Scopes:       scopes,
	}
	return provider, cfg, true, nil
}

// handleOIDCLogin starts the auth-code flow with PKCE and a nonce. It is
// unauthenticated, so what it costs is bounded: starts are counted per client
// address, discovery is cached, and a full table of pending sign-ins refuses
// the new one rather than dropping someone else's.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.oidcStarts.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts, try again later")
		return
	}
	s.oidcStarts.fail(ip)
	_, cfg, ok, err := s.oidcConfig(r)
	if err != nil {
		// The IdP's answer, or the misconfiguration, is for the operator's log,
		// not for whoever hit the unauthenticated endpoint.
		log.Printf("admin: oidc login: %v", err)
		writeErr(w, http.StatusBadGateway, "the identity provider is not available right now; details are in the server log")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "OIDC not configured")
		return
	}
	state, err := newSessionID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nonce, err := newSessionID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	login := adminOIDCLogin{nonce: nonce, verifier: oauth2.GenerateVerifier(), expires: time.Now().Add(adminOIDCLoginTTL)}
	s.mu.Lock()
	now := time.Now()
	for k, l := range s.oidcLogins {
		if now.After(l.expires) {
			delete(s.oidcLogins, k)
		}
	}
	if len(s.oidcLogins) >= adminOIDCMaxPending {
		s.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "too many sign-ins are in progress; try again in a few minutes")
		return
	}
	s.oidcLogins[state] = login
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "qg_oidc_state", Value: state, Path: "/api/oidc/", HttpOnly: true,
		Secure: isHTTPS(r), MaxAge: int(adminOIDCLoginTTL.Seconds()), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(login.verifier), oidc.Nonce(login.nonce)), http.StatusFound)
}

// handleOIDCCallback consumes the sign-in, exchanges the code with its PKCE
// verifier, verifies the ID token and its nonce, and, if the address is a
// local admin or explicitly allowed, mints a session.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("qg_oidc_state")
	if err != nil || state == "" || state != stateCookie.Value {
		writeErr(w, http.StatusBadRequest, "state mismatch")
		return
	}
	s.mu.Lock()
	login, pending := s.oidcLogins[state]
	delete(s.oidcLogins, state) // one use, whatever happens next
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "qg_oidc_state", Value: "", Path: "/api/oidc/", HttpOnly: true, Secure: isHTTPS(r), MaxAge: -1})
	if !pending || time.Now().After(login.expires) {
		writeErr(w, http.StatusBadRequest, "this sign-in expired or was already used; start again")
		return
	}
	ctx := oidcClientContext(r.Context())
	provider, cfg, ok, err := s.oidcConfig(r)
	if err != nil || !ok {
		if err != nil {
			log.Printf("admin: oidc callback: %v", err)
		}
		writeErr(w, http.StatusBadGateway, "OIDC not available")
		return
	}
	oauth2Token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(login.verifier))
	if err != nil {
		// The error carries the IdP's response body; that is for the log.
		log.Printf("admin: oidc token exchange failed: %v", err)
		writeErr(w, http.StatusBadRequest, "the identity provider did not accept the sign-in; details are in the server log")
		return
	}
	rawID, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no id_token in response")
		return
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "id_token verification failed")
		return
	}
	if idToken.Nonce != login.nonce {
		writeErr(w, http.StatusUnauthorized, "nonce mismatch")
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
	if err := s.startSession(w, r, u.ID, email); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
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
