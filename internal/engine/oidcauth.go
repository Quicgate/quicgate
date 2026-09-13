package engine

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"quicgate/internal/store"
)

// Built-in OpenID Connect SSO for proxied hosts. The engine itself runs the
// auth-code flow (with PKCE and a nonce) against the configured provider and
// keeps a stateless, HMAC-signed session cookie per host, so no Authelia-style
// sidecar is needed. Every gated host reserves /.qg/oidc/callback (the
// redirect URI to register at the IdP) and /.qg/oidc/logout.
//
// The cookie is bound to the exact host it was minted for: one shared signing
// secret must not let a session for grafana.example.com replay against
// vault.example.com, since the two may trust different groups.

const (
	oidcCallbackPath = "/.qg/oidc/callback"
	oidcLogoutPath   = "/.qg/oidc/logout"
	oidcSessionName  = "qg_id"
	oidcStateName    = "qg_oidc_state"
)

// identityHeaders are always stripped from inbound requests on a host with
// OIDC configured (public paths included) so a client can never spoof them,
// and injected upstream when the host opts in to passIdentity.
var identityHeaders = []string{"Remote-User", "Remote-Email", "Remote-Groups"}

// oidcSession is the signed cookie payload. Short JSON keys keep the cookie
// small; groups can be long lists on directory-backed IdPs.
type oidcSession struct {
	Email  string   `json:"e"`
	Groups []string `json:"g,omitempty"`
	Host   string   `json:"h"`
	Expiry int64    `json:"x"`
	Prov   int64    `json:"p"` // provider that authenticated this session
}

// oidcState carries the in-flight login through the redirect round-trip.
type oidcState struct {
	Return   string `json:"r"` // original requestURI to land back on
	Nonce    string `json:"n"`
	Verifier string `json:"v"` // PKCE code verifier
	Host     string `json:"h"`
	Expiry   int64  `json:"x"`
	Prov     int64  `json:"p"` // provider whose login is in flight
	// Gate identifies the policy that started the login (see oidcGateKey), so
	// the callback is finished, and authorised, by that gate and no other.
	Gate string `json:"k"`
}

// discoveredProvider caches the (network-fetched) OIDC discovery result per
// issuer so a reload never blocks on the IdP and a down IdP is retried gently.
type discoveredProvider struct {
	provider *oidc.Provider
	err      error
	fetched  time.Time
}

func (e *Engine) oidcDiscover(r *http.Request, p store.OIDCProvider) (*oidc.Provider, error) {
	key := p.Issuer + "|" + boolKey(p.SkipTLSVerify)
	if v, ok := e.oidcProviders.Load(key); ok {
		d := v.(*discoveredProvider)
		if d.err == nil || time.Since(d.fetched) < 30*time.Second {
			return d.provider, d.err
		}
	}
	provider, err := oidc.NewProvider(idpContext(r.Context(), p), p.Issuer)
	if err != nil {
		log.Printf("oidc: discovery for %s failed: %v", p.Issuer, err)
	}
	e.oidcProviders.Store(key, &discoveredProvider{provider: provider, err: err, fetched: time.Now()})
	return provider, err
}

// idpContext carries the HTTP client for every request to the provider
// (discovery, token exchange, key set): always bounded by a timeout, and
// skipping certificate verification only when the provider is configured to.
func idpContext(ctx context.Context, p store.OIDCProvider) context.Context {
	if p.SkipTLSVerify {
		return oidc.ClientContext(ctx, idpInsecureClient)
	}
	return oidc.ClientContext(ctx, idpClient)
}

// The IdP clients are shared, so their connections are pooled and reused
// instead of a new transport (and its idle connections) per login.
var (
	idpClient         = &http.Client{Timeout: 15 * time.Second}
	idpInsecureClient = func() *http.Client {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		return &http.Client{Timeout: 15 * time.Second, Transport: t}
	}()
)

func boolKey(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// oidcSecret returns the process-wide cookie-signing secret, generating and
// persisting it on first use so sessions survive restarts.
func (e *Engine) oidcSecret() []byte {
	e.oidcSecretMu.Lock()
	defer e.oidcSecretMu.Unlock()
	if len(e.oidcSecretKey) > 0 {
		return e.oidcSecretKey
	}
	if hexKey := e.store.GetSetting("sso_cookie_secret", ""); hexKey != "" {
		if key, err := hex.DecodeString(hexKey); err == nil && len(key) == 32 {
			e.oidcSecretKey = key
			return key
		}
	}
	key := make([]byte, 32)
	rand.Read(key)
	if err := e.store.SetSetting("sso_cookie_secret", hex.EncodeToString(key)); err != nil {
		log.Printf("oidc: persisting cookie secret failed (sessions will not survive a restart): %v", err)
	}
	e.oidcSecretKey = key
	return key
}

// syncOIDCSecret applies a replaced or cleared sso_cookie_secret to the running
// gates. Without it the key stayed cached in memory until a restart, so the
// documented way to sign everybody out (clearing the key) and a restore did
// nothing to sessions already issued. Called on every reload.
func (e *Engine) syncOIDCSecret() {
	hexKey := e.store.GetSetting("sso_cookie_secret", "")
	e.oidcSecretMu.Lock()
	defer e.oidcSecretMu.Unlock()
	if key, err := hex.DecodeString(hexKey); err == nil && len(key) == 32 {
		e.oidcSecretKey = key
		return
	}
	// Cleared or unusable: the next use generates and persists a fresh key.
	e.oidcSecretKey = nil
}

// oidcGate is one compiled OIDC policy: a provider plus who it admits. A host
// has one per distinct policy (its own, and each path rule that names one), and
// gates on the same provider share discovery and token verification but never
// their policy.
type oidcGate struct {
	engine   *engineOIDC
	provider store.OIDCProvider
	auth     store.OIDCAuth
	key      string // oidcGateKey(auth)
	// siblings lets whichever gate receives the shared callback path hand the
	// request to the gate whose login is actually in flight. Keyed by gate key,
	// wired once per host at reload.
	siblings map[string]*oidcGate
}

// oidcGateKey identifies a policy: the provider and every policy field. Two
// rules with the same key are the same gate; any difference (another allowed
// group, passIdentity) makes a separate one.
func oidcGateKey(auth store.OIDCAuth) string {
	b, _ := json.Marshal(auth)
	sum := sha256.Sum256(b)
	return strconv.FormatInt(auth.ProviderID, 10) + ":" + hex.EncodeToString(sum[:8])
}

// engineOIDC is the tiny slice of Engine the gate needs; a separate type keeps
// oidcGate constructible in tests without a full engine.
type engineOIDC struct {
	secret   func() []byte
	discover func(*http.Request, store.OIDCProvider) (*oidc.Provider, error)
}

// newOIDCGate resolves the host's provider reference. A missing provider
// fails closed: the gate still exists and answers 403 instead of proxying.
func (e *Engine) newOIDCGate(auth store.OIDCAuth, providers map[int64]store.OIDCProvider) *oidcGate {
	g := &oidcGate{engine: &engineOIDC{secret: e.oidcSecret, discover: e.oidcDiscover}, auth: auth, key: oidcGateKey(auth)}
	if p, ok := providers[auth.ProviderID]; ok {
		g.provider = p
	}
	return g
}

// sign MACs payload for one purpose (the cookie name). The login state and the
// session are signed with the same key and their JSON shares field names, so
// without the purpose a state cookie, which every anonymous visitor receives,
// verified as a session.
func (g *oidcGate) sign(purpose string, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(g.mac(purpose, payload))
}

func (g *oidcGate) mac(purpose string, payload []byte) []byte {
	mac := hmac.New(sha256.New, g.engine.secret())
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write(payload)
	return mac.Sum(nil)
}

func (g *oidcGate) verify(purpose, value string, out any) bool {
	dot := strings.IndexByte(value, '.')
	if dot < 0 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(value[:dot])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(value[dot+1:])
	if err != nil {
		return false
	}
	if !hmac.Equal(sig, g.mac(purpose, payload)) {
		return false
	}
	return json.Unmarshal(payload, out) == nil
}

// allowed applies the host's policy to a verified identity. Empty lists mean
// any authenticated user.
func (g *oidcGate) allowed(email string, groups []string) bool {
	a := g.auth
	if len(a.AllowedEmails) == 0 && len(a.AllowedDomains) == 0 && len(a.AllowedGroups) == 0 {
		return true
	}
	email = strings.ToLower(email)
	for _, e := range a.AllowedEmails {
		if e == email {
			return true
		}
	}
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		domain := email[at+1:]
		for _, d := range a.AllowedDomains {
			if d == domain {
				return true
			}
		}
	}
	for _, want := range a.AllowedGroups {
		for _, have := range groups {
			if want == have {
				return true
			}
		}
	}
	return false
}

func requestHostname(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return host
}

func (g *oidcGate) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: requestIsTLS(r), SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

// session returns the request's valid session, or nil.
func (g *oidcGate) session(r *http.Request) *oidcSession {
	c, err := r.Cookie(oidcSessionName)
	if err != nil {
		return nil
	}
	var s oidcSession
	if !g.verify(oidcSessionName, c.Value, &s) {
		return nil
	}
	// Bound to the host it was minted for AND to the provider that issued it.
	// Without the provider check, a host whose /partner path trusts a second
	// IdP would accept a session from that IdP on its staff-only paths: log in
	// wherever you can get an account, walk in everywhere.
	if s.Host != requestHostname(r) || s.Prov != g.provider.ID || time.Now().Unix() > s.Expiry {
		return nil
	}
	return &s
}

// wrap gates next behind the OIDC login. CORS preflights pass, matching the
// access-list gate: they carry no credentials by spec.
func (g *oidcGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case oidcCallbackPath:
			g.handleCallback(w, r)
			return
		case oidcLogoutPath:
			g.setCookie(w, r, oidcSessionName, "", -1)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if isCORSPreflight(r) {
			next.ServeHTTP(w, r)
			return
		}
		if g.provider.ID == 0 {
			http.Error(w, "OIDC provider not configured", http.StatusForbidden)
			return
		}
		if s := g.session(r); s != nil {
			if !g.allowed(s.Email, s.Groups) {
				http.Error(w, "forbidden: "+s.Email+" is not permitted here", http.StatusForbidden)
				return
			}
			markIdentified(r)
			if g.auth.PassIdentity {
				r.Header.Set("Remote-User", s.Email)
				r.Header.Set("Remote-Email", s.Email)
				r.Header.Set("Remote-Groups", strings.Join(s.Groups, ","))
			}
			next.ServeHTTP(w, r)
			return
		}
		g.startLogin(w, r)
	})
}

// claimIsTrue reads a boolean claim that some providers send as a string.
func claimIsTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (g *oidcGate) oauthConfig(r *http.Request, provider *oidc.Provider) oauth2.Config {
	scheme := "http"
	if requestIsTLS(r) {
		scheme = "https"
	}
	scopes := g.provider.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return oauth2.Config{
		ClientID:     g.provider.ClientID,
		ClientSecret: g.provider.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  scheme + "://" + r.Host + oidcCallbackPath,
		Scopes:       scopes,
	}
}

func (g *oidcGate) startLogin(w http.ResponseWriter, r *http.Request) {
	provider, err := g.engine.discover(r, g.provider)
	if err != nil {
		http.Error(w, "identity provider unreachable", http.StatusBadGateway)
		return
	}
	st := oidcState{
		Return:   r.URL.RequestURI(),
		Nonce:    randToken(),
		Verifier: oauth2.GenerateVerifier(),
		Host:     requestHostname(r),
		Expiry:   time.Now().Add(5 * time.Minute).Unix(),
		Prov:     g.provider.ID,
		Gate:     g.key,
	}
	payload, _ := json.Marshal(st)
	signed := g.sign(oidcStateName, payload)
	g.setCookie(w, r, oidcStateName, signed, 300)
	cfg := g.oauthConfig(r, provider)
	// The state parameter only needs to tie the callback to this cookie; the
	// full payload rides in the cookie itself.
	http.Redirect(w, r, cfg.AuthCodeURL(st.Nonce,
		oauth2.S256ChallengeOption(st.Verifier), oidc.Nonce(st.Nonce)), http.StatusFound)
}

func (g *oidcGate) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(oidcStateName)
	if err != nil {
		http.Error(w, "login session expired, retry", http.StatusBadRequest)
		return
	}
	var st oidcState
	if !g.verify(oidcStateName, c.Value, &st) || st.Host != requestHostname(r) ||
		time.Now().Unix() > st.Expiry || r.URL.Query().Get("state") != st.Nonce {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	// Another gate may have started this login: a path rule can name its own
	// IdP, or its own policy on the same IdP, and every one of them redirects
	// back to the same callback path. The state cookie is signed, so its gate
	// key decides who finishes the flow and whose policy is applied.
	if st.Gate != g.key {
		if other := g.siblings[st.Gate]; other != nil && other != g {
			other.handleCallback(w, r)
			return
		}
		http.Error(w, "this login was started for a policy this host no longer uses, retry", http.StatusBadRequest)
		return
	}
	g.setCookie(w, r, oidcStateName, "", -1)
	provider, err := g.engine.discover(r, g.provider)
	if err != nil {
		http.Error(w, "identity provider unreachable", http.StatusBadGateway)
		return
	}
	cfg := g.oauthConfig(r, provider)
	ctx := idpContext(r.Context(), g.provider)
	token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusBadGateway)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: g.provider.ClientID}).Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != st.Nonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "cannot read claims", http.StatusBadGateway)
		return
	}
	email, _ := claims["email"].(string)
	if email == "" {
		// Some IdPs put the address in preferred_username instead.
		email, _ = claims["preferred_username"].(string)
	}
	if email == "" {
		http.Error(w, "identity token carries no email", http.StatusForbidden)
		return
	}
	// An unverified address must not satisfy an allowed-emails or
	// allowed-domains policy: on IdPs where users can set their own address,
	// that would let anyone claim to be someone@yourcompany.com. Providers that
	// omit the claim entirely are taken at their word.
	if v, present := claims["email_verified"]; present && !claimIsTrue(v) {
		http.Error(w, "identity provider reports this address as unverified", http.StatusForbidden)
		return
	}
	var groups []string
	if raw, ok := claims[g.provider.GroupsClaim].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	if !g.allowed(email, groups) {
		http.Error(w, "forbidden: "+email+" is not permitted here", http.StatusForbidden)
		return
	}
	ttl := time.Duration(g.provider.SessionHours) * time.Hour
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	sess := oidcSession{Email: strings.ToLower(email), Groups: groups,
		Host: requestHostname(r), Prov: g.provider.ID, Expiry: time.Now().Add(ttl).Unix()}
	payload, _ := json.Marshal(sess)
	g.setCookie(w, r, oidcSessionName, g.sign(oidcSessionName, payload), int(ttl.Seconds()))
	// Only ever return to a same-host relative path: the value came back
	// through a signed cookie, but defence in depth costs one check.
	dest := st.Return
	// Browsers treat a backslash as a path separator in some positions, so
	// "/\evil.com" can become protocol-relative; CR/LF would split the header.
	if !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") ||
		strings.ContainsAny(dest, "\\\r\n") {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// normalizeHeaderName folds a header name the way many application servers do
// when they turn headers into variables: case-insensitive, with "_" and "-"
// equivalent.
func normalizeHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// stripHeaders removes the named headers from every inbound request before any
// gate runs, public paths included, so an upstream that trusts identity
// headers can never be fed a spoofed value through quicgate. Only a gate that
// has just authenticated the request puts them back.
func stripHeaders(names []string, next http.Handler) http.Handler {
	if len(names) == 0 {
		return next
	}
	strip := make(map[string]bool, len(names))
	for _, h := range names {
		strip[normalizeHeaderName(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match every spelling, not just the canonical one: Remote_User reaches
		// the same variable as Remote-User in many application servers.
		for k := range r.Header {
			if strip[normalizeHeaderName(k)] {
				delete(r.Header, k)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// trustedIdentityHeaders lists every header name a gate on this host may inject
// upstream: the Remote-* set when any SSO gate exists (host-level or on any
// path rule) and the forward-auth response headers when forward auth is set.
func trustedIdentityHeaders(o store.Options) []string {
	var names []string
	sso := o.OIDC != nil
	for _, r := range o.AuthRules {
		if r.Mode == "oidc" {
			sso = true
		}
	}
	if sso {
		names = append(names, identityHeaders...)
	}
	if o.ForwardAuth != nil && o.ForwardAuth.URL != "" {
		for _, h := range o.ForwardAuth.ResponseHeaders {
			if h = strings.TrimSpace(h); h != "" {
				names = append(names, h)
			}
		}
	}
	return names
}
