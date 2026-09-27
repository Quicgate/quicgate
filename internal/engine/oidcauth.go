package engine

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
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
	// oidcMaxSession bounds a session's lifetime whatever the provider row
	// says (the store refuses more, older rows may still carry more): sessions
	// are stateless and cannot be revoked one by one.
	oidcMaxSession = time.Duration(store.MaxSessionHours) * time.Hour
)

// identityHeaders are always stripped from inbound requests on a host with
// any identity gate (public paths included) so a client can never spoof them,
// and injected upstream when an OIDC gate opts in to passIdentity.
var identityHeaders = []string{"Remote-User", "Remote-Email", "Remote-Groups"}

// ssoCookieNames are the cookies of the built-in SSO: a credential for this
// host in the browser's hands and nobody else's business. stripHeaders takes
// them out of the Cookie header, so they never reach an upstream or a
// forward-auth server, and hands them to the gate through the context.
var ssoCookieNames = []string{oidcSessionName, oidcStateName}

// oidcSession is the signed cookie payload. Short JSON keys keep the cookie
// small; groups can be long lists on directory-backed IdPs.
type oidcSession struct {
	Email  string   `json:"e"`
	Groups []string `json:"g,omitempty"`
	Host   string   `json:"h"`
	Expiry int64    `json:"x"`
	Prov   int64    `json:"p"` // provider that authenticated this session
	// Unverified: the address came from preferred_username and the provider
	// did not vouch for it. It names the person, but satisfies no e-mail or
	// domain rule of the policy; groups still do.
	Unverified bool `json:"u,omitempty"`
}

// oidcState carries the in-flight login through the redirect round-trip.
type oidcState struct {
	Return   string `json:"r"` // original requestURI to land back on
	State    string `json:"s"` // the state parameter the callback must carry
	Nonce    string `json:"n"` // the nonce the ID token must carry
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
	refresh  time.Time // when to ask the issuer again
}

const (
	oidcDiscoveryTimeout = 15 * time.Second
	oidcDiscoveryRefresh = time.Hour        // a good result is asked for again after this
	oidcDiscoveryRetry   = 10 * time.Second // a failed one is retried after this
)

// oidcDiscover fetches, or serves from the cache, the provider's discovery
// document. It runs under a context of its own, never the client's: a browser
// that gives up mid-redirect must not turn into a cached failure that closes
// the gate for everyone else. A good result is refreshed after an hour, so a
// moved endpoint is picked up without a restart; a failure is retried after
// ten seconds; while a refresh fails the last good result stays in use.
func (e *Engine) oidcDiscover(p store.OIDCProvider) (*oidc.Provider, error) {
	key := p.Issuer + "|" + boolKey(p.SkipTLSVerify)
	var last *discoveredProvider
	if v, ok := e.oidcProviders.Load(key); ok {
		last = v.(*discoveredProvider)
		if time.Now().Before(last.refresh) {
			return last.provider, last.err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(idpContext(ctx, p), p.Issuer)
	if err != nil {
		log.Printf("oidc: discovery for %s failed: %v", p.Issuer, err)
		if last != nil && last.err == nil {
			e.oidcProviders.Store(key, &discoveredProvider{provider: last.provider, refresh: time.Now().Add(oidcDiscoveryRetry)})
			return last.provider, nil
		}
		e.oidcProviders.Store(key, &discoveredProvider{err: err, refresh: time.Now().Add(oidcDiscoveryRetry)})
		return nil, err
	}
	e.oidcProviders.Store(key, &discoveredProvider{provider: provider, refresh: time.Now().Add(oidcDiscoveryRefresh)})
	return provider, nil
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

const ssoSecretSetting = "sso_cookie_secret"

// oidcSecret returns the process-wide cookie-signing key, or nil when there is
// none that can be used. Every reload loads it (syncOIDCSecret), making and
// persisting one on first use so sessions survive restarts; this is the
// fallback for a request that arrives before that. A stored key that does not
// open (the store is locked, or the database was restored from an instance
// with another sealing key) is never replaced: that would sign everyone out
// for good while the right key could still have come back (QG-04). Single
// sign-on closes instead, and the reload says why in the log.
func (e *Engine) oidcSecret() []byte {
	e.oidcSecretMu.Lock()
	defer e.oidcSecretMu.Unlock()
	if len(e.oidcSecretKey) == 0 {
		e.oidcSecretKey, _ = e.loadSSOSecret()
	}
	return e.oidcSecretKey
}

// syncOIDCSecret applies a replaced or cleared sso_cookie_secret to the running
// gates, and makes a key when none is stored. Without it the key stayed cached
// in memory until a restart, so the documented way to sign everybody out
// (clearing the key) and a restore did nothing to sessions already issued.
// Called on every reload; what keeps single sign-on closed is logged here,
// once per reload.
func (e *Engine) syncOIDCSecret() {
	e.oidcSecretMu.Lock()
	defer e.oidcSecretMu.Unlock()
	key, problem := e.loadSSOSecret()
	if problem != "" {
		log.Printf("oidc: %s", problem)
	}
	e.oidcSecretKey = key
}

// loadSSOSecret reads the signing key from the store, making and persisting
// one when nothing is stored. It returns the key, or nil with the reason there
// is none. Called with e.oidcSecretMu held.
func (e *Engine) loadSSOSecret() ([]byte, string) {
	key, problem := decodeSSOSecret(e.store.SecretSetting(ssoSecretSetting))
	if key != nil || problem != "" {
		return key, problem
	}
	// Nothing is stored: first use. The write only happens if that is still
	// so; otherwise whatever appeared meanwhile is used.
	key = make([]byte, 32)
	rand.Read(key)
	stored, err := e.store.InitSecretSetting(ssoSecretSetting, hex.EncodeToString(key))
	if err != nil {
		return nil, "the SSO cookie signing key cannot be stored, single sign-on stays closed: " + err.Error()
	}
	if stored {
		return key, ""
	}
	key, problem = decodeSSOSecret(e.store.SecretSetting(ssoSecretSetting))
	if key == nil && problem == "" {
		problem = "the SSO cookie signing key vanished while it was being made; single sign-on stays closed until the next reload"
	}
	return key, problem
}

// decodeSSOSecret turns what the store holds under sso_cookie_secret into a
// key. It returns the key, or nil when nothing usable is stored: with a
// problem when something is stored that must not be replaced by a new key,
// and without one when the setting is simply unset.
func decodeSSOSecret(hexKey string, state store.SecretState) (key []byte, problem string) {
	switch state {
	case store.SecretUnreadable:
		return nil, "the SSO cookie signing key is stored but cannot be opened with the sealing key in use; " +
			"single sign-on is closed until the original secret.key is back, or the key is reset (Sessions: sign everyone out of SSO)"
	case store.SecretReadable:
		if key, err := hex.DecodeString(hexKey); err == nil && len(key) == 32 {
			return key, ""
		}
		return nil, "sso_cookie_secret is set but is not a 64-character hex key; single sign-on is closed until it is cleared (Sessions: sign everyone out of SSO), which makes a new one"
	}
	return nil, ""
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
	discover func(store.OIDCProvider) (*oidc.Provider, error)
	// devNoTLS is a development instance started without TLS altogether
	// (QG_TLS=off): the one place the gate works over plain HTTP.
	devNoTLS bool
}

// newOIDCGate resolves the host's provider reference. A missing provider
// fails closed: the gate still exists and answers 403 instead of proxying.
func (e *Engine) newOIDCGate(auth store.OIDCAuth, providers map[int64]store.OIDCProvider) *oidcGate {
	g := &oidcGate{engine: &engineOIDC{secret: e.oidcSecret, discover: e.oidcDiscover, devNoTLS: e.cfg.DisableTLS}, auth: auth, key: oidcGateKey(auth)}
	if p, ok := providers[auth.ProviderID]; ok {
		g.provider = p
	}
	return g
}

// errNoSigningKey: there is no cookie-signing key to use (see oidcSecret).
// Nothing is signed with a made-up one, and nothing verifies.
var errNoSigningKey = errors.New("the SSO cookie signing key is not available")

// sign MACs payload for one purpose (the cookie name). The login state and the
// session are signed with the same key and their JSON shares field names, so
// without the purpose a state cookie, which every anonymous visitor receives,
// verified as a session.
func (g *oidcGate) sign(purpose string, payload []byte) (string, error) {
	mac, err := g.mac(purpose, payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (g *oidcGate) mac(purpose string, payload []byte) ([]byte, error) {
	key := g.engine.secret()
	if len(key) == 0 {
		return nil, errNoSigningKey
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write(payload)
	return mac.Sum(nil), nil
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
	want, err := g.mac(purpose, payload)
	if err != nil || !hmac.Equal(sig, want) {
		return false
	}
	return json.Unmarshal(payload, out) == nil
}

// allowed applies the host's policy to a verified identity. Empty lists mean
// any authenticated user. An address the provider did not vouch for
// (emailTrusted false) satisfies no e-mail or domain rule: only its groups can
// admit it.
func (g *oidcGate) allowed(email string, groups []string, emailTrusted bool) bool {
	a := g.auth
	if len(a.AllowedEmails) == 0 && len(a.AllowedDomains) == 0 && len(a.AllowedGroups) == 0 {
		return true
	}
	if emailTrusted {
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
	// Always Secure. The one exception is a development instance that was
	// started without TLS altogether, where there is no HTTPS to send it on.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: connectionEncrypted(r) || !g.engine.devNoTLS, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

// session returns the request's valid session, or nil.
func (g *oidcGate) session(r *http.Request) *oidcSession {
	value, ok := ssoCookie(r, oidcSessionName)
	if !ok {
		return nil
	}
	var s oidcSession
	if !g.verify(oidcSessionName, value, &s) {
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
		// The gate mints a cookie that is a credential for this host and runs
		// a login whose redirect has to come back over the same scheme. Over
		// plain HTTP anybody on the path reads the cookie, so there is no gate
		// over plain HTTP (QG-05, as for the VPN portal): the browser is sent
		// to HTTPS, anything else is refused. A development instance without
		// TLS altogether is the one exception.
		if !connectionEncrypted(r) && !g.engine.devNoTLS {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
				return
			}
			http.Error(w, "single sign-on is only served over HTTPS", http.StatusForbidden)
			return
		}
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
			markBlocked(w, blockSSO)
			http.Error(w, "OIDC provider not configured", http.StatusForbidden)
			return
		}
		if s := g.session(r); s != nil {
			if !g.allowed(s.Email, s.Groups, !s.Unverified) {
				markBlocked(w, blockSSO)
				http.Error(w, "forbidden: "+s.Email+" is not permitted here", http.StatusForbidden)
				return
			}
			markIdentified(r)
			if g.auth.PassIdentity {
				r.Header.Set("Remote-User", s.Email)
				r.Header.Set("Remote-Email", s.Email)
				r.Header.Set("Remote-Groups", headerList(s.Groups))
			}
			next.ServeHTTP(w, r)
			return
		}
		g.startLogin(w, r)
	})
}

// headerList joins values for a comma-separated header so that the delimiter
// can never appear inside one: a comma, a percent sign and the control
// characters (a CR/LF would end the header) are percent-encoded, so a group
// "Sales, EMEA" arrives as the one group "Sales%2C EMEA" and never as two.
func headerList(values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = encodeListItem(v)
	}
	return strings.Join(out, ",")
}

func encodeListItem(v string) string {
	if strings.IndexFunc(v, func(r rune) bool { return r == ',' || r == '%' || r < 0x20 || r == 0x7f }) < 0 {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if c := v[i]; c == ',' || c == '%' || c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
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
	if connectionEncrypted(r) {
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

// ssoUnavailable answers a request the gate cannot serve because there is no
// cookie-signing key (see oidcSecret): nothing is minted or accepted.
func ssoUnavailable(w http.ResponseWriter) {
	http.Error(w, "single sign-on is unavailable: the cookie signing key cannot be read (see the server log)", http.StatusServiceUnavailable)
}

func (g *oidcGate) startLogin(w http.ResponseWriter, r *http.Request) {
	st := oidcState{
		Return:   r.URL.RequestURI(),
		State:    randToken(),
		Nonce:    randToken(),
		Verifier: oauth2.GenerateVerifier(),
		Host:     requestHostname(r),
		Expiry:   time.Now().Add(5 * time.Minute).Unix(),
		Prov:     g.provider.ID,
		Gate:     g.key,
	}
	payload, _ := json.Marshal(st)
	// Signed before the provider is asked anything: without a key there is
	// no login to start.
	signed, err := g.sign(oidcStateName, payload)
	if err != nil {
		ssoUnavailable(w)
		return
	}
	provider, err := g.engine.discover(g.provider)
	if err != nil {
		http.Error(w, "identity provider unreachable", http.StatusBadGateway)
		return
	}
	g.setCookie(w, r, oidcStateName, signed, 300)
	cfg := g.oauthConfig(r, provider)
	// The state parameter only needs to tie the callback to this cookie; the
	// full payload rides in the cookie itself. The nonce is a value of its own:
	// the state is visible in the callback URL, the nonce only inside the
	// signed ID token.
	http.Redirect(w, r, cfg.AuthCodeURL(st.State,
		oauth2.S256ChallengeOption(st.Verifier), oidc.Nonce(st.Nonce)), http.StatusFound)
}

func (g *oidcGate) handleCallback(w http.ResponseWriter, r *http.Request) {
	value, ok := ssoCookie(r, oidcStateName)
	if !ok {
		http.Error(w, "login session expired, retry", http.StatusBadRequest)
		return
	}
	var st oidcState
	if !g.verify(oidcStateName, value, &st) || st.Host != requestHostname(r) || time.Now().Unix() > st.Expiry ||
		subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(st.State)) != 1 {
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
	if code := r.URL.Query().Get("error"); code != "" {
		// The provider answered the login with an error instead of a code:
		// the person declined, or the client is misconfigured there. Say so,
		// rather than posting an empty code to the token endpoint.
		desc := r.URL.Query().Get("error_description")
		log.Printf("oidc: %s: the identity provider refused a login: %s (%s)", requestHostname(r), clip(code, 80), clip(desc, 200))
		writeLoginRefused(w, code, desc, safeReturn(st.Return))
		return
	}
	provider, err := g.engine.discover(g.provider)
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
		markBlocked(w, blockSSO)
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != st.Nonce {
		markBlocked(w, blockSSO)
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "cannot read claims", http.StatusBadGateway)
		return
	}
	email, _ := claims["email"].(string)
	fromUsername := false
	if email == "" {
		// Some IdPs put the address in preferred_username instead.
		email, _ = claims["preferred_username"].(string)
		fromUsername = true
	}
	if email == "" {
		markBlocked(w, blockSSO)
		http.Error(w, "identity token carries no email", http.StatusForbidden)
		return
	}
	// An unverified address must not satisfy an allowed-emails or
	// allowed-domains policy: on IdPs where users can set their own address,
	// that would let anyone claim to be someone@yourcompany.com. Providers that
	// omit the claim entirely are taken at their word.
	if v, present := claims["email_verified"]; present && !claimIsTrue(v) {
		markBlocked(w, blockSSO)
		http.Error(w, "identity provider reports this address as unverified", http.StatusForbidden)
		return
	}
	// A user name the provider does not vouch for as an address is a name,
	// not a mailbox: it is taken at its word for nothing but who to call the
	// person. Only the groups can admit it, unless the provider says the
	// address is verified.
	unverified := fromUsername && !claimIsTrue(claims["email_verified"])
	var groups []string
	if raw, ok := claims[g.provider.GroupsClaim].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	if !g.allowed(email, groups, !unverified) {
		markBlocked(w, blockSSO)
		http.Error(w, "forbidden: "+email+" is not permitted here", http.StatusForbidden)
		return
	}
	ttl := time.Duration(g.provider.SessionHours) * time.Hour
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if ttl > oidcMaxSession {
		ttl = oidcMaxSession
	}
	sess := oidcSession{Email: strings.ToLower(email), Groups: groups, Unverified: unverified,
		Host: requestHostname(r), Prov: g.provider.ID, Expiry: time.Now().Add(ttl).Unix()}
	payload, _ := json.Marshal(sess)
	signed, err := g.sign(oidcSessionName, payload)
	if err != nil {
		ssoUnavailable(w)
		return
	}
	g.setCookie(w, r, oidcSessionName, signed, int(ttl.Seconds()))
	http.Redirect(w, r, safeReturn(st.Return), http.StatusFound)
}

// safeReturn keeps a post-login destination on this host: only ever a relative
// path. The value came back through a signed cookie, but defence in depth
// costs one check. Browsers treat a backslash as a path separator in some
// positions, so "/\evil.com" can become protocol-relative; CR/LF would split
// the header.
func safeReturn(dest string) string {
	if !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") ||
		strings.ContainsAny(dest, "\\\r\n") {
		return "/"
	}
	return dest
}

// clip shortens a value from the callback URL for the log and the page: the
// provider's description is short, anything longer is not the provider's.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// writeLoginRefused is the page for a login the identity provider answered
// with an error. Both values come from the callback URL, so they are shown
// escaped and cut short.
func writeLoginRefused(w http.ResponseWriter, code, desc, retry string) {
	msg := "the identity provider refused the login: " + htmlEscape(clip(code, 80))
	if desc != "" {
		msg += " (" + htmlEscape(clip(desc, 200)) + ")"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Login refused</title>
<style>body{background:#0e0f13;color:#eef1f4;font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0}
div{text-align:center;max-width:40em}h1{margin:0 0 .5em}p{color:#8b97a8}a{color:#a3e635}</style></head>
<body><div><h1>Login refused</h1><p>%s</p><p><a href="%s">Try again</a></p></div></body></html>`, msg, htmlEscape(retry))
}

// normalizeHeaderName folds a header name the way many application servers do
// when they turn headers into variables: case-insensitive, with "_" and "-"
// equivalent.
func normalizeHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// ssoCookiesKey carries quicgate's own SSO cookies, taken out of the Cookie
// header by stripHeaders, to the gate that reads them.
type ssoCookiesKey struct{}

// ssoCookie returns one of quicgate's own cookies: from where stripHeaders put
// it, or from the header when the request did not pass through it.
func ssoCookie(r *http.Request, name string) (string, bool) {
	if taken, ok := r.Context().Value(ssoCookiesKey{}).(map[string]string); ok {
		v, ok := taken[name]
		return v, ok
	}
	c, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

// takeCookies removes the named cookies from the Cookie header, leaving every
// other cookie as it was sent, and returns what it took (the first value of a
// name, as r.Cookie would). The header goes when nothing is left.
func takeCookies(h http.Header, names []string) map[string]string {
	lines := h["Cookie"]
	if len(lines) == 0 {
		return nil
	}
	var taken map[string]string
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		var keep []string
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, value, _ := strings.Cut(part, "=")
			if !slices.Contains(names, name) {
				keep = append(keep, part)
				continue
			}
			if taken == nil {
				taken = map[string]string{}
			}
			if _, dup := taken[name]; !dup {
				taken[name] = value
			}
		}
		if len(keep) > 0 {
			kept = append(kept, strings.Join(keep, "; "))
		}
	}
	if taken == nil {
		return nil
	}
	if len(kept) == 0 {
		h.Del("Cookie")
	} else {
		h["Cookie"] = kept
	}
	return taken
}

// stripHeaders removes the named headers from every inbound request before any
// gate runs, public paths included, so an upstream that trusts identity
// headers can never be fed a spoofed value through quicgate. Only a gate that
// has just authenticated the request puts them back. It also takes quicgate's
// own SSO cookies out of the Cookie header (see ssoCookieNames): the gate
// reads them from the context, the upstream never sees them.
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
		if taken := takeCookies(r.Header, ssoCookieNames); len(taken) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), ssoCookiesKey{}, taken))
		}
		next.ServeHTTP(w, r)
	})
}

// trustedIdentityHeaders lists every header name a gate on this host may inject
// upstream, or that an upstream behind it may trust: the Remote-* set whenever
// any identity gate exists (SSO or forward auth, host-level or on any path
// rule), and the forward-auth response headers when forward auth is set. A
// forward-auth host whose upstream reads Remote-User must not get the
// client's own value just because the auth server was told to send another
// name.
func trustedIdentityHeaders(o store.Options) []string {
	forward := o.ForwardAuth != nil && o.ForwardAuth.URL != ""
	identity := o.OIDC != nil || forward
	for _, r := range o.AuthRules {
		if r.Mode == "oidc" || r.Mode == "forwardAuth" {
			identity = true
		}
	}
	var names []string
	if identity {
		names = append(names, identityHeaders...)
	}
	if forward {
		for _, h := range o.ForwardAuth.ResponseHeaders {
			if h = strings.TrimSpace(h); h != "" {
				names = append(names, h)
			}
		}
	}
	return names
}
