package engine

import (
	"context"
	"crypto/tls"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"quicgate/internal/store"
)

// newTLSTestEngine makes an ordinary engine (TLS on), unlike newTestEngine's
// development instance without TLS: what the gate does over plain HTTP can
// only be seen on one.
func newTLSTestEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := New(Config{DataDir: dir}, st)
	t.Cleanup(func() { e.wg.Close(); _ = e.accessLog.Close(); _ = e.ban.closePersist() })
	return e, st
}

// send drives one request through handler as a listener would hand it over:
// over an encrypted connection or not.
func send(handler http.Handler, method, host, path, remote string, encrypted bool, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = remote
	if encrypted {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	return rr
}

// F-4: a provider that answers the login with an error (the person declined
// consent, the client is misconfigured there) gets a clear answer, not a token
// exchange with an empty code and a 502. The description is the provider's, or
// anybody's who can make the browser open the URL, so it is shown escaped.
func TestOIDCIdPErrorIsAnsweredNotExchanged(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"deny.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)

	r1 := req(e, "GET", "deny.test", "/app?x=1", "203.0.113.9", nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("login start: %d", r1.Code)
	}
	loc, _ := url.Parse(r1.Header().Get("Location"))
	q := url.Values{"error": {"access_denied"}, "error_description": {"<b>User denied</b> access"}, "state": {loc.Query().Get("state")}}
	rr := req(e, "GET", "deny.test", oidcCallbackPath+"?"+q.Encode(), "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a callback carrying the provider's error: %d %q, want 403", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "the identity provider refused the login: access_denied") {
		t.Fatalf("the page does not say what happened: %q", body)
	}
	if strings.Contains(body, "<b>") || !strings.Contains(body, "&lt;b&gt;User denied&lt;/b&gt;") {
		t.Fatalf("the provider's description is echoed unescaped: %q", body)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q, want an HTML page", ct)
	}
	if !strings.Contains(body, `href="/app?x=1"`) {
		t.Fatalf("the page does not lead back to where the login started: %q", body)
	}
	if n := idp.tokenCalls.Load(); n != 0 {
		t.Fatalf("the token endpoint was asked %d times for a code that does not exist", n)
	}
	var stateCleared, session bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == oidcStateName && c.MaxAge < 0 {
			stateCleared = true
		}
		if c.Name == oidcSessionName {
			session = true
		}
	}
	if !stateCleared || session {
		t.Fatalf("state cookie cleared: %v, session minted: %v; want the login spent and nothing minted", stateCleared, session)
	}
	// Without the login's own state the error is not even looked at.
	rr = req(e, "GET", "deny.test", oidcCallbackPath+"?error=access_denied&state=other", "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an error with a foreign state: %d, want 400", rr.Code)
	}
}

// M-13 (QG-05 for the gate): the SSO gate mints a credential and runs a login
// whose redirect has to come back over the same scheme, so it does not work
// over plain HTTP: the browser is sent to HTTPS, anything else is refused, no
// cookie is set, and a session presented over plain HTTP opens nothing. TLS at
// a trusted proxy in front counts when that proxy says so; the header from
// anybody else does not. The one exception is a development instance without
// TLS at all, which every other test here runs on.
func TestOIDCGateNeedsHTTPS(t *testing.T) {
	e, st := newTLSTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	var hits atomic.Int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"sso.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h) // no force-SSL: port 80 hands the host to its chain
	reload(t, e)

	plain := http.HandlerFunc(e.serveHTTP)
	const client = "203.0.113.9:50000"
	rr := send(plain, "GET", "sso.test", "/protected?a=1", client, false, nil)
	if rr.Code != http.StatusPermanentRedirect || rr.Header().Get("Location") != "https://sso.test/protected?a=1" || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("plain HTTP: %d to %q with cookies %v, want a 308 to HTTPS and no cookie", rr.Code, rr.Header().Get("Location"), rr.Result().Cookies())
	}
	if rr := send(plain, "HEAD", "sso.test", "/protected", client, false, nil); rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("HEAD over plain HTTP: %d, want 308", rr.Code)
	}
	if rr := send(plain, "POST", "sso.test", "/protected", client, false, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("POST over plain HTTP: %d, want 403", rr.Code)
	}
	// A header anybody can send does not make the connection encrypted.
	if rr := send(plain, "GET", "sso.test", "/protected", client, false, map[string]string{"X-Forwarded-Proto": "https"}); rr.Code != http.StatusPermanentRedirect || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("X-Forwarded-Proto from a stranger was believed: %d, cookies %v", rr.Code, rr.Result().Cookies())
	}
	// The reserved paths are no exception: a callback over plain HTTP would
	// mint the session over it.
	if rr := send(plain, "GET", "sso.test", oidcCallbackPath+"?code=c&state=s", client, false, nil); rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("the callback over plain HTTP: %d, want 308", rr.Code)
	}

	// Over TLS the login runs, with Secure cookies and an https redirect URI.
	secure := http.HandlerFunc(e.serveHTTPS)
	r1 := send(secure, "GET", "sso.test", "/protected?a=1", client, true, nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("login over TLS: %d %q", r1.Code, r1.Body.String())
	}
	loc, _ := url.Parse(r1.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://sso.test"+oidcCallbackPath {
		t.Fatalf("redirect_uri = %q, want https", got)
	}
	for _, c := range r1.Result().Cookies() {
		if !c.Secure {
			t.Fatalf("cookie %s set over TLS is not Secure", c.Name)
		}
	}
	idp.nonce = loc.Query().Get("nonce")
	r2 := send(secure, "GET", "sso.test", oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"), client, true, map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusFound {
		t.Fatalf("callback over TLS: %d %q", r2.Code, r2.Body.String())
	}
	session := cookieHeader(r2)
	for _, c := range r2.Result().Cookies() {
		if c.Name == oidcSessionName && !c.Secure {
			t.Fatal("the session cookie is not Secure")
		}
	}
	if rr := send(secure, "GET", "sso.test", "/protected", client, true, map[string]string{"Cookie": session}); rr.Code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("the session over TLS: %d, upstream hits %d", rr.Code, hits.Load())
	}
	// The session is worth nothing over plain HTTP.
	if rr := send(plain, "GET", "sso.test", "/protected", client, false, map[string]string{"Cookie": session}); rr.Code != http.StatusPermanentRedirect || hits.Load() != 1 {
		t.Fatalf("the session over plain HTTP: %d, upstream hits %d; want a 308 and no upstream request", rr.Code, hits.Load())
	}

	// TLS at a trusted proxy in front counts, when that proxy says so...
	setSettings(t, st, map[string]string{"trusted_proxies": "10.0.0.0/8", "real_ip_header": "X-Forwarded-For"})
	reload(t, e)
	viaProxy := e.wrapRealIP(plain)
	fromProxy := map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https", "Cookie": session}
	if rr := send(viaProxy, "GET", "sso.test", "/protected", "10.1.2.3:4000", false, fromProxy); rr.Code != http.StatusOK || hits.Load() != 2 {
		t.Fatalf("behind a trusted TLS-terminating proxy: %d, upstream hits %d; want 200", rr.Code, hits.Load())
	}
	// ...and only when it says so.
	delete(fromProxy, "X-Forwarded-Proto")
	if rr := send(viaProxy, "GET", "sso.test", "/protected", "10.1.2.3:4000", false, fromProxy); rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("plain HTTP behind a trusted proxy: %d, want 308", rr.Code)
	}
}

// L-46: the SSO cookies are quicgate's, and a credential for this host: the
// upstream never sees them, on gated and on public paths alike, and neither
// does a forward-auth server. Every other cookie arrives as it was sent.
func TestSSOCookiesStayOutOfTheUpstream(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	var seen []string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Values("Cookie")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"ck.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	h.Options.AuthRules = []store.AuthRule{{Path: "/public", Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	session := oidcLogin(t, e, idp, "ck.test") // "qg_id=..."
	rr := req(e, "GET", "ck.test", "/app", "203.0.113.9", map[string]string{"Cookie": "theme=dark; " + session + "; lang=nl"})
	if rr.Code != http.StatusOK || len(seen) != 1 || seen[0] != "theme=dark; lang=nl" {
		t.Fatalf("code %d, upstream saw Cookie %q, want the other cookies only", rr.Code, seen)
	}
	rr = req(e, "GET", "ck.test", "/app", "203.0.113.9", map[string]string{"Cookie": session})
	if rr.Code != http.StatusOK || len(seen) != 0 {
		t.Fatalf("the session cookie alone: code %d, upstream saw Cookie %q, want no header at all", rr.Code, seen)
	}
	// A login in flight (the state cookie) does not go upstream either, and a
	// public carve-out is no exception.
	r1 := req(e, "GET", "ck.test", "/other", "203.0.113.9", nil)
	rr = req(e, "GET", "ck.test", "/public/x", "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1) + "; " + session + "; a=1"})
	if rr.Code != http.StatusOK || len(seen) != 1 || seen[0] != "a=1" {
		t.Fatalf("public path: code %d, upstream saw Cookie %q, want a=1", rr.Code, seen)
	}
	// Cookies split over several header lines, as HTTP/2 clients may send them.
	r := httptest.NewRequest("GET", "http://ck.test/app", nil)
	r.Host, r.RemoteAddr = "ck.test", "203.0.113.9:50000"
	r.Header["Cookie"] = []string{"a=1; " + session, "b=2"}
	rec := httptest.NewRecorder()
	e.serveHTTPS(rec, r)
	if rec.Code != http.StatusOK || strings.Join(seen, "|") != "a=1|b=2" {
		t.Fatalf("split Cookie headers: code %d, upstream saw %q", rec.Code, seen)
	}

	// Forward auth sees the client's cookies, minus quicgate's own.
	var authSaw string
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSaw = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(auth.Close)
	fa := &store.Host{Type: "proxy", Domains: []string{"fack.test"}, Upstream: up}
	fa.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL, ResponseHeaders: []string{"Remote-User"}}
	mustCreateHost(t, st, fa)
	reload(t, e)
	rr = req(e, "GET", "fack.test", "/", "203.0.113.9", map[string]string{"Cookie": "authelia_session=abc; " + oidcSessionName + "=stale"})
	if rr.Code != http.StatusOK || authSaw != "authelia_session=abc" || strings.Join(seen, "|") != "authelia_session=abc" {
		t.Fatalf("forward auth host: code %d, auth server saw %q, upstream saw %q", rr.Code, authSaw, seen)
	}
}

// L-24: Remote-Groups is comma-separated, so a group whose name holds a comma
// (or a line break) must not be able to spell extra groups, or headers.
func TestRemoteGroupsCannotBeInjected(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	idp.groups = []string{"admins", "sales,emea", "x\r\ny", "100%"}
	pid := mustCreateOIDCProvider(t, st, idp)
	var groups string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		groups = r.Header.Get("Remote-Groups")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"grp.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"admins"}, PassIdentity: true}
	mustCreateHost(t, st, h)
	reload(t, e)

	cookie := oidcLogin(t, e, idp, "grp.test")
	rr := req(e, "GET", "grp.test", "/", "203.0.113.9", map[string]string{"Cookie": cookie})
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated request: %d %q", rr.Code, rr.Body.String())
	}
	if want := "admins,sales%2Cemea,x%0D%0Ay,100%25"; groups != want {
		t.Fatalf("upstream saw Remote-Groups %q, want %q", groups, want)
	}
	if n := len(strings.Split(groups, ",")); n != 4 {
		t.Fatalf("the upstream would read %d groups, want the 4 the provider named", n)
	}
}

// L-25: the Remote-* identity headers are stripped on every host with an
// identity gate, forward auth included, not only where SSO is configured: an
// upstream behind forward auth may trust Remote-User whatever header name the
// auth server was told to send.
func TestIdentityHeadersStrippedOnForwardAuthOnlyHost(t *testing.T) {
	e, st := newTestEngine(t)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-User", "real")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(auth.Close)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		var leaked []string
		for k := range r.Header {
			switch normalizeHeaderName(k) {
			case "remote-user", "remote-email", "remote-groups":
				leaked = append(leaked, k)
			}
		}
		sort.Strings(leaked)
		seen = strings.Join(leaked, ",") + "|" + r.Header.Get("X-Auth-User")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"faonly.test"}, Upstream: up}
	h.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL, ResponseHeaders: []string{"X-Auth-User"}}
	h.Options.AuthRules = []store.AuthRule{{Path: "/webhook", Exact: true, Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	forged := map[string]string{"Remote-User": "forged@evil", "Remote_Email": "forged@evil", "REMOTE-GROUPS": "admins", "X-Auth-User": "forged"}
	if rr := req(e, "GET", "faonly.test", "/app", "203.0.113.9", forged); rr.Code != http.StatusOK || seen != "|real" {
		t.Fatalf("gated path: code %d, upstream saw %q; want no Remote-* header and the auth server's X-Auth-User", rr.Code, seen)
	}
	if rr := req(e, "GET", "faonly.test", "/webhook", "203.0.113.9", forged); rr.Code != http.StatusOK || seen != "|" {
		t.Fatalf("public carve-out: code %d, upstream saw %q; want no identity header at all", rr.Code, seen)
	}
}

// L-26: an address the provider only knows as a user name (preferred_username,
// no email claim) names the person but proves nothing about a mailbox: it
// satisfies no e-mail or domain rule unless the provider says it is verified.
// Groups still admit it, and a session so admitted is re-checked with that
// knowledge when the policy changes.
func TestPreferredUsernameSatisfiesNoEmailRule(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.groups = []string{"staff"}
	idp.mutate = func(c map[string]any) {
		delete(c, "email")
		delete(c, "email_verified")
		c["preferred_username"] = "Anna@Example.com"
	}
	pid := mustCreateOIDCProvider(t, st, idp)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	byDomain := &store.Host{Type: "proxy", Domains: []string{"dom.test"}, Upstream: up}
	byDomain.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedDomains: []string{"example.com"}, PassIdentity: true}
	mustCreateHost(t, st, byDomain)
	byGroup := &store.Host{Type: "proxy", Domains: []string{"team.test"}, Upstream: up}
	byGroup.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"staff"}, PassIdentity: true}
	mustCreateHost(t, st, byGroup)
	reload(t, e)

	// A domain rule: refused at the callback, no session.
	r1 := req(e, "GET", "dom.test", "/", "203.0.113.9", nil)
	loc, _ := url.Parse(r1.Header().Get("Location"))
	idp.nonce = loc.Query().Get("nonce")
	cb := req(e, "GET", "dom.test", oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"), "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if cb.Code != http.StatusForbidden || strings.Contains(cookieHeader(cb), oidcSessionName) {
		t.Fatalf("a user name against a domain rule: %d %q, cookies %q; want 403 and no session", cb.Code, cb.Body.String(), cookieHeader(cb))
	}
	// A group rule: admitted, and the name is what the upstream is told.
	session := oidcLoginAt(t, e, idp, "team.test", "/home")
	if rr := req(e, "GET", "team.test", "/home", "203.0.113.9", map[string]string{"Cookie": session}); rr.Code != http.StatusOK || seen != "anna@example.com" {
		t.Fatalf("a user name against a group rule: %d, Remote-User %q; want 200 and the name", rr.Code, seen)
	}
	// The policy is re-checked on every request with what the session knows:
	// the host switches to a domain rule, and the same session is refused.
	hosts, err := st.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Domains[0] == "team.test" {
			h.Options.OIDC.AllowedGroups, h.Options.OIDC.AllowedDomains = nil, []string{"example.com"}
			if err := st.UpdateHost(&h); err != nil {
				t.Fatal(err)
			}
		}
	}
	reload(t, e)
	if rr := req(e, "GET", "team.test", "/home", "203.0.113.9", map[string]string{"Cookie": session}); rr.Code != http.StatusForbidden {
		t.Fatalf("the session of an unverified name against a domain rule: %d, want 403", rr.Code)
	}
	// With the provider's word for the address, a domain rule admits it.
	idp.mutate = func(c map[string]any) {
		delete(c, "email")
		c["preferred_username"] = "anna@example.com"
		c["email_verified"] = true
	}
	verified := oidcLoginAt(t, e, idp, "dom.test", "/")
	if rr := req(e, "GET", "dom.test", "/", "203.0.113.9", map[string]string{"Cookie": verified}); rr.Code != http.StatusOK {
		t.Fatalf("a verified user name against a domain rule: %d, want 200", rr.Code)
	}
}

// SSO-16: the state, visible in the callback URL, and the nonce, inside the
// signed ID token, are two values: neither stands in for the other.
func TestOIDCStateAndNonceAreDistinct(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"sn.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)

	r1 := req(e, "GET", "sn.test", "/", "203.0.113.9", nil)
	loc, _ := url.Parse(r1.Header().Get("Location"))
	state, nonce := loc.Query().Get("state"), loc.Query().Get("nonce")
	if state == "" || nonce == "" || state == nonce {
		t.Fatalf("state %q and nonce %q, want two distinct random values", state, nonce)
	}
	idp.nonce = nonce
	if rr := req(e, "GET", "sn.test", oidcCallbackPath+"?code=c1&state="+nonce, "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)}); rr.Code != http.StatusBadRequest {
		t.Fatalf("the nonce presented as the state: %d, want 400", rr.Code)
	}
	if rr := req(e, "GET", "sn.test", oidcCallbackPath+"?code=c1&state="+state, "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)}); rr.Code != http.StatusFound {
		t.Fatalf("the state itself: %d %q, want the login to complete", rr.Code, rr.Body.String())
	}
}

// L-27: discovery runs under a context of its own, never the client's. A
// visitor that gives up mid-redirect must not turn into a cached failure that
// closes the gate for everyone after them.
func TestOIDCDiscoveryIgnoresTheClientsContext(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"disc.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)

	// The first visitor is gone before discovery starts.
	r := httptest.NewRequest("GET", "http://disc.test/", nil)
	r.Host, r.RemoteAddr = "disc.test", "203.0.113.9:50000"
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	rr := httptest.NewRecorder()
	e.serveHTTPS(rr, r.WithContext(ctx))
	if rr.Code != http.StatusFound {
		t.Fatalf("a visitor who left: %d %q, want the login to start regardless", rr.Code, rr.Body.String())
	}
	if rr := req(e, "GET", "disc.test", "/", "203.0.113.9", nil); rr.Code != http.StatusFound {
		t.Fatalf("the next visitor: %d %q, want a redirect to the provider, not a cached failure", rr.Code, rr.Body.String())
	}
}

// L-27: a provider that is down is not asked again on every request, but it is
// asked again soon; and a good result is kept while a refresh of it fails.
func TestOIDCDiscoveryRetriesAProviderThatWasDown(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"down.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)
	// expire makes every cached discovery result due for a refresh.
	expire := func() {
		e.oidcProviders.Range(func(k, v any) bool {
			d := *v.(*discoveredProvider)
			d.refresh = time.Now().Add(-time.Second)
			e.oidcProviders.Store(k, &d)
			return true
		})
	}

	idp.down.Store(true)
	if rr := req(e, "GET", "down.test", "/", "203.0.113.9", nil); rr.Code != http.StatusBadGateway {
		t.Fatalf("with the provider down: %d, want 502", rr.Code)
	}
	idp.down.Store(false)
	if rr := req(e, "GET", "down.test", "/", "203.0.113.9", nil); rr.Code != http.StatusBadGateway {
		t.Fatalf("right after a failure: %d, want the failure remembered for a moment", rr.Code)
	}
	expire()
	if rr := req(e, "GET", "down.test", "/", "203.0.113.9", nil); rr.Code != http.StatusFound {
		t.Fatalf("once the failure is due for a retry: %d %q, want the login to start", rr.Code, rr.Body.String())
	}
	// A good result outlives a provider that is down when it is refreshed.
	idp.down.Store(true)
	expire()
	if rr := req(e, "GET", "down.test", "/", "203.0.113.9", nil); rr.Code != http.StatusFound {
		t.Fatalf("a refresh that failed threw the last good result away: %d", rr.Code)
	}
}

// L-31: the session lifetime is capped at 30 days in the gate too, for a
// provider row saved before the store refused more.
func TestOIDCSessionLifetimeIsCapped(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	db, err := sql.Open("sqlite", filepath.Join(e.cfg.DataDir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE oidc_providers SET session_hours = 5000 WHERE id = ?", pid); err != nil {
		t.Fatal(err)
	}
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"long.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)

	r1 := req(e, "GET", "long.test", "/", "203.0.113.9", nil)
	loc, _ := url.Parse(r1.Header().Get("Location"))
	idp.nonce = loc.Query().Get("nonce")
	r2 := req(e, "GET", "long.test", oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"), "203.0.113.9", map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusFound {
		t.Fatalf("callback: %d %q", r2.Code, r2.Body.String())
	}
	for _, c := range r2.Result().Cookies() {
		if c.Name == oidcSessionName && c.MaxAge != store.MaxSessionHours*3600 {
			t.Fatalf("session cookie Max-Age %d, want the cap of %d hours", c.MaxAge, store.MaxSessionHours)
		}
	}
}
