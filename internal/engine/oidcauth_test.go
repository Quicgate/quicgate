package engine

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"quicgate/internal/store"
)

// fakeIdP is a minimal OpenID Connect provider: discovery, JWKS, and a token
// endpoint that returns an RS256-signed id_token for whatever identity the
// test configures. The authorize endpoint is never actually served — tests
// parse the redirect and jump straight to quicgate's callback, as a browser
// would after the IdP round-trip.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	email  string
	groups []string
	nonce  string // captured from the token request? No: set by test from the auth redirect
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.srv.URL
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/auth",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer",
			"id_token": idp.signIDToken(t),
		})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (f *fakeIdP) signIDToken(t *testing.T) string {
	t.Helper()
	claims := map[string]any{
		"iss": f.srv.URL, "aud": "quicgate-test", "sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": f.email, "email_verified": true, "nonce": f.nonce,
	}
	if f.groups != nil {
		claims["groups"] = f.groups
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	body, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mustCreateOIDCProvider(t *testing.T, st *store.Store, idp *fakeIdP) int64 {
	t.Helper()
	p := &store.OIDCProvider{Name: "test-idp", Issuer: idp.srv.URL, ClientID: "quicgate-test", ClientSecret: "s3cret"}
	if err := st.CreateOIDCProvider(p); err != nil {
		t.Fatalf("create provider: %v", err)
	}
	return p.ID
}

// cookieHeader joins recorder Set-Cookie values into a request Cookie header.
func cookieHeader(rrs ...*httptest.ResponseRecorder) string {
	var pairs []string
	for _, rr := range rrs {
		for _, sc := range rr.Result().Cookies() {
			if sc.MaxAge >= 0 && sc.Value != "" {
				pairs = append(pairs, sc.Name+"="+sc.Value)
			}
		}
	}
	return strings.Join(pairs, "; ")
}

// login walks the full flow for one host and returns the session cookie pair.
func oidcLogin(t *testing.T, e *Engine, idp *fakeIdP, host string) string {
	t.Helper()
	// 1. Anonymous request redirects to the IdP with a state cookie.
	r1 := req(e, "GET", host, "/protected?a=1", "203.0.113.9", nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("anonymous request: got %d, want 302 (body %q)", r1.Code, r1.Body.String())
	}
	loc, err := url.Parse(r1.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), idp.srv.URL) {
		t.Fatalf("redirect went to %q, want the IdP", r1.Header().Get("Location"))
	}
	state := loc.Query().Get("state")
	if state == "" || loc.Query().Get("code_challenge") == "" {
		t.Fatalf("auth URL misses state or PKCE challenge: %s", loc)
	}
	idp.nonce = loc.Query().Get("nonce")

	// 2. The IdP "redirects back" to the callback with a code.
	r2 := req(e, "GET", host, oidcCallbackPath+"?code=c1&state="+state, "203.0.113.9",
		map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302 (body %q)", r2.Code, r2.Body.String())
	}
	if got := r2.Header().Get("Location"); got != "/protected?a=1" {
		t.Fatalf("post-login redirect = %q, want the original URL", got)
	}
	c := cookieHeader(r2)
	if !strings.Contains(c, oidcSessionName+"=") {
		t.Fatal("callback set no session cookie")
	}
	return c
}

func TestOIDCFullFlow(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "gijs@example.com"
	idp.groups = []string{"admins"}
	pid := mustCreateOIDCProvider(t, st, idp)

	var seenUser, seenSpoof string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seenUser = r.Header.Get("Remote-User")
		seenSpoof = r.Header.Get("Remote-Groups")
		w.Write([]byte("secret content"))
	})
	h := &store.Host{Type: "proxy", Domains: []string{"sso.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"admins"}, PassIdentity: true}
	mustCreateHost(t, st, h)
	reload(t, e)

	cookie := oidcLogin(t, e, idp, "sso.test")

	// 3. The session cookie now reaches the upstream, with identity injected
	// and the spoofed inbound header stripped.
	r3 := req(e, "GET", "sso.test", "/protected?a=1", "203.0.113.9",
		map[string]string{"Cookie": cookie, "Remote-User": "spoofed@evil"})
	if r3.Code != http.StatusOK || r3.Body.String() != "secret content" {
		t.Fatalf("authenticated request: got %d %q", r3.Code, r3.Body.String())
	}
	if seenUser != "gijs@example.com" {
		t.Fatalf("upstream saw Remote-User %q, want the session identity", seenUser)
	}
	if seenSpoof != "admins" {
		t.Fatalf("upstream saw Remote-Groups %q, want the session groups", seenSpoof)
	}

	// 4. Logout clears the cookie and the next request bounces to the IdP.
	r4 := req(e, "GET", "sso.test", oidcLogoutPath, "203.0.113.9", map[string]string{"Cookie": cookie})
	if r4.Code != http.StatusFound {
		t.Fatalf("logout: got %d, want 302", r4.Code)
	}
	r5 := req(e, "GET", "sso.test", "/protected", "203.0.113.9", nil)
	if r5.Code != http.StatusFound || !strings.HasPrefix(r5.Header().Get("Location"), idp.srv.URL) {
		t.Fatalf("after logout: got %d -> %q, want a redirect to the IdP", r5.Code, r5.Header().Get("Location"))
	}
}

func TestOIDCGroupPolicyDenies(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "intern@example.com"
	idp.groups = []string{"interns"}
	pid := mustCreateOIDCProvider(t, st, idp)

	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"gp.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"admins"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	r1 := req(e, "GET", "gp.test", "/", "203.0.113.9", nil)
	loc, _ := url.Parse(r1.Header().Get("Location"))
	idp.nonce = loc.Query().Get("nonce")
	r2 := req(e, "GET", "gp.test", oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"),
		"203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusForbidden {
		t.Fatalf("wrong group at callback: got %d, want 403", r2.Code)
	}
}

// A session minted for one host must not unlock another gated host, even
// though both cookies are signed with the same process-wide secret.
func TestOIDCSessionIsHostBound(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "gijs@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)

	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, d := range []string{"one.test", "two.test"} {
		h := &store.Host{Type: "proxy", Domains: []string{d}, Upstream: up}
		h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
		mustCreateHost(t, st, h)
	}
	reload(t, e)

	cookie := oidcLogin(t, e, idp, "one.test")
	if rr := req(e, "GET", "one.test", "/x", "203.0.113.9", map[string]string{"Cookie": cookie}); rr.Code != http.StatusOK {
		t.Fatalf("own host: got %d, want 200", rr.Code)
	}
	rr := req(e, "GET", "two.test", "/x", "203.0.113.9", map[string]string{"Cookie": cookie})
	if rr.Code != http.StatusFound {
		t.Fatalf("replayed cookie on another host: got %d, want a 302 back to the IdP", rr.Code)
	}
}

// Path rules compose with OIDC: a public carve-out stays reachable without a
// login, and its inbound identity headers are still stripped.
func TestOIDCWithPublicPathRule(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "gijs@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)

	var gotUser string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Remote-User")
		fmt.Fprint(w, "ok")
	})
	h := &store.Host{Type: "proxy", Domains: []string{"mix.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, PassIdentity: true}
	h.Options.AuthRules = []store.AuthRule{{Path: "/webhook", Exact: true, Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	rr := req(e, "GET", "mix.test", "/webhook", "203.0.113.9", map[string]string{"Remote-User": "spoofed@evil"})
	if rr.Code != http.StatusOK {
		t.Fatalf("public path: got %d, want 200 without login", rr.Code)
	}
	if gotUser != "" {
		t.Fatalf("spoofed Remote-User %q leaked through the public path", gotUser)
	}
	if rr := req(e, "GET", "mix.test", "/app", "203.0.113.9", nil); rr.Code != http.StatusFound {
		t.Fatalf("gated path: got %d, want 302 to the IdP", rr.Code)
	}
}

// A dangling provider reference fails closed instead of proxying.
func TestOIDCMissingProviderFailsClosed(t *testing.T) {
	e, _ := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// The store refuses a dangling provider, so inject the row past validation.
	h := store.Host{Type: "proxy", Domains: []string{"mp.test"}, Upstream: up, CertMode: "none", Enabled: true}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: 4242}
	e.SetDockerRoutes([]store.Host{h}, nil)

	if rr := req(e, "GET", "mp.test", "/", "203.0.113.9", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("missing provider: got %d, want 403", rr.Code)
	}
}

// A host that gates only part of its paths with SSO must still complete the
// login: the IdP redirects back to /.qg/oidc/callback, which matches no rule.
func TestOIDCCallbackReachableWithPathRules(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "gijs@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)

	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"part.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	// Everything is public except /admin/, which requires the SSO login.
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/", Mode: "public"},
		{Path: "/admin/", Mode: "oidc"},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	if rr := req(e, "GET", "part.test", "/", "203.0.113.9", nil); rr.Code != http.StatusOK {
		t.Fatalf("public root: got %d, want 200", rr.Code)
	}
	r1 := req(e, "GET", "part.test", "/admin/panel", "203.0.113.9", nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("gated path: got %d, want 302 to the IdP", r1.Code)
	}
	loc, _ := url.Parse(r1.Header().Get("Location"))
	idp.nonce = loc.Query().Get("nonce")
	// The callback would otherwise be swallowed by the "/" public rule.
	r2 := req(e, "GET", "part.test", oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"),
		"203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302 (body %q)", r2.Code, r2.Body.String())
	}
	if !strings.Contains(cookieHeader(r2), oidcSessionName+"=") {
		t.Fatal("callback set no session cookie")
	}
}

// One host, two identity providers: /staff logs in against one IdP and
// /partner against another. Both redirect back to the same callback path, so
// this also proves the callback reaches the provider that started the login.
func TestOIDCPerPathProviders(t *testing.T) {
	e, st := newTestEngine(t)
	staffIdP := newFakeIdP(t)
	staffIdP.email = "employee@example.com"
	partnerIdP := newFakeIdP(t)
	partnerIdP.email = "contractor@partner.test"

	staffID := mustCreateOIDCProvider(t, st, staffIdP)
	p := &store.OIDCProvider{Name: "partner-idp", Issuer: partnerIdP.srv.URL, ClientID: "quicgate-test", ClientSecret: "s"}
	if err := st.CreateOIDCProvider(p); err != nil {
		t.Fatalf("create partner provider: %v", err)
	}

	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"multi.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: staffID, PassIdentity: true}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/partner/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: p.ID, PassIdentity: true}},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	// The gated default path goes to the staff IdP...
	r1 := req(e, "GET", "multi.test", "/staff", "203.0.113.9", nil)
	if r1.Code != http.StatusFound || !strings.HasPrefix(r1.Header().Get("Location"), staffIdP.srv.URL) {
		t.Fatalf("/staff went to %q, want the staff IdP", r1.Header().Get("Location"))
	}
	// ...and the partner path to the partner IdP.
	r2 := req(e, "GET", "multi.test", "/partner/x", "203.0.113.9", nil)
	if r2.Code != http.StatusFound || !strings.HasPrefix(r2.Header().Get("Location"), partnerIdP.srv.URL) {
		t.Fatalf("/partner/x went to %q, want the partner IdP", r2.Header().Get("Location"))
	}

	// Finish the partner login. The callback path is not under /partner/, so it
	// is served by the host's staff gate and must be handed to the partner one.
	loc, _ := url.Parse(r2.Header().Get("Location"))
	partnerIdP.nonce = loc.Query().Get("nonce")
	r3 := req(e, "GET", "multi.test", oidcCallbackPath+"?code=c&state="+loc.Query().Get("state"),
		"203.0.113.9", map[string]string{"Cookie": cookieHeader(r2)})
	if r3.Code != http.StatusFound {
		t.Fatalf("partner callback: got %d, want 302 (body %q)", r3.Code, r3.Body.String())
	}
	if got := r3.Header().Get("Location"); got != "/partner/x" {
		t.Fatalf("partner callback returned to %q, want /partner/x", got)
	}

	cookie := cookieHeader(r3)
	if rr := req(e, "GET", "multi.test", "/partner/x", "203.0.113.9", map[string]string{"Cookie": cookie}); rr.Code != http.StatusOK {
		t.Fatalf("partner path with its session: got %d, want 200", rr.Code)
	}
	if seen != "contractor@partner.test" {
		t.Fatalf("upstream saw %q, want the partner identity", seen)
	}
	// The partner session must not unlock the staff-gated part of the host.
	if rr := req(e, "GET", "multi.test", "/staff", "203.0.113.9", map[string]string{"Cookie": cookie}); rr.Code != http.StatusFound {
		t.Fatalf("partner session on a staff path: got %d, want a redirect to the staff IdP", rr.Code)
	}
}
