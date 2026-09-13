package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// oidcLoginAt walks the login flow starting from path on host and returns the
// session cookie. Unlike oidcLogin it lets the caller pick where the login
// starts, because with per-path policies the gate that starts it matters.
func oidcLoginAt(t *testing.T, e *Engine, idp *fakeIdP, host, path string) string {
	t.Helper()
	r1 := req(e, "GET", host, path, "203.0.113.9", nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("anonymous %s: got %d, want 302 (body %q)", path, r1.Code, r1.Body.String())
	}
	loc, err := url.Parse(r1.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	idp.nonce = loc.Query().Get("nonce")
	r2 := req(e, "GET", host, oidcCallbackPath+"?code=c1&state="+loc.Query().Get("state"), "203.0.113.9",
		map[string]string{"Cookie": cookieHeader(r1)})
	if r2.Code != http.StatusFound {
		t.Fatalf("callback after %s: got %d, want 302 (body %q)", path, r2.Code, r2.Body.String())
	}
	c := cookieHeader(r2)
	if !strings.Contains(c, oidcSessionName+"=") {
		t.Fatalf("callback after %s set no session cookie", path)
	}
	return c
}

// Q02: a stricter path policy on the SAME provider as the host must be enforced
// on its own. The host admits employees; /admin/ admits only admins.
func TestOIDCSameProviderPathPolicyIsSeparate(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })

	h := &store.Host{Type: "proxy", Domains: []string{"corp.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"employees"}}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/admin/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"admins"}}},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	idp.email, idp.groups = "employee@example.com", []string{"employees"}
	emp := oidcLoginAt(t, e, idp, "corp.test", "/wiki")
	if rr := req(e, "GET", "corp.test", "/wiki", "203.0.113.9", map[string]string{"Cookie": emp}); rr.Code != http.StatusOK {
		t.Fatalf("employee on the host path: got %d, want 200", rr.Code)
	}
	if rr := req(e, "GET", "corp.test", "/admin/secrets", "203.0.113.9", map[string]string{"Cookie": emp}); rr.Code != http.StatusForbidden {
		t.Fatalf("employee on /admin/: got %d body %q, want 403", rr.Code, rr.Body.String())
	}

	idp.email, idp.groups = "boss@example.com", []string{"employees", "admins"}
	boss := oidcLoginAt(t, e, idp, "corp.test", "/admin/panel")
	for _, p := range []string{"/admin/secrets", "/wiki"} {
		if rr := req(e, "GET", "corp.test", p, "203.0.113.9", map[string]string{"Cookie": boss}); rr.Code != http.StatusOK {
			t.Fatalf("admin on %s: got %d, want 200", p, rr.Code)
		}
	}
}

// Q02: the reverse shape. The host is narrow (admins) and a path is broader
// (employees); logging in through the broad path must not open the host.
func TestOIDCSameProviderBroadPathNarrowHost(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })

	h := &store.Host{Type: "proxy", Domains: []string{"ops.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"admins"}}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/status/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: pid, AllowedGroups: []string{"employees"}}},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	idp.email, idp.groups = "employee@example.com", []string{"employees"}
	emp := oidcLoginAt(t, e, idp, "ops.test", "/status/board")
	if rr := req(e, "GET", "ops.test", "/status/board", "203.0.113.9", map[string]string{"Cookie": emp}); rr.Code != http.StatusOK {
		t.Fatalf("employee on the broad path: got %d, want 200", rr.Code)
	}
	if rr := req(e, "GET", "ops.test", "/console", "203.0.113.9", map[string]string{"Cookie": emp}); rr.Code != http.StatusForbidden {
		t.Fatalf("employee on the admins-only host path: got %d, want 403", rr.Code)
	}
}

// Q02: passIdentity belongs to the gate that matched, not to whichever gate on
// the provider was built first.
func TestOIDCSameProviderPassIdentityPerGate(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"pass.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/app/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: pid, PassIdentity: true}},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	c := oidcLoginAt(t, e, idp, "pass.test", "/home")
	if rr := req(e, "GET", "pass.test", "/app/x", "203.0.113.9", map[string]string{"Cookie": c}); rr.Code != http.StatusOK || seen != "anna@example.com" {
		t.Fatalf("/app/ with passIdentity: code=%d Remote-User=%q, want 200 and the identity", rr.Code, seen)
	}
	seen = "unset"
	if rr := req(e, "GET", "pass.test", "/home", "203.0.113.9", map[string]string{"Cookie": c}); rr.Code != http.StatusOK || seen != "" {
		t.Fatalf("host path without passIdentity: code=%d Remote-User=%q, want 200 and no identity header", rr.Code, seen)
	}
}

// Q06: a host whose only SSO is on one path must still strip spoofed identity
// headers from every other path.
func TestIdentityHeadersStrippedWithPathOnlyOIDC(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Remote-User") + "|" + r.Header.Get("Remote-Email") + "|" + r.Header.Get("Remote-Groups")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"pathsso.test"}, Upstream: up}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/admin/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: pid, PassIdentity: true}},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	rr := req(e, "GET", "pathsso.test", "/public/profile", "203.0.113.9", map[string]string{
		"Remote-User": "forged-admin@example.com", "Remote-Email": "forged-admin@example.com", "Remote-Groups": "admins",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("public path: got %d, want 200", rr.Code)
	}
	if seen != "||" {
		t.Fatalf("upstream received spoofed identity headers %q on a path-only SSO host", seen)
	}
}

// Q06: forward auth owns its response headers on the whole host, including a
// public carve-out that never runs the forward-auth check.
func TestForwardAuthHeadersStrippedOnPublicCarveOut(t *testing.T) {
	e, st := newTestEngine(t)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Remote-User", "real-user")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(auth.Close)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"fa.test"}, Upstream: up}
	h.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL, ResponseHeaders: []string{"Remote-User"}}
	h.Options.AuthRules = []store.AuthRule{{Path: "/webhook", Exact: true, Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	if rr := req(e, "GET", "fa.test", "/webhook", "203.0.113.9", map[string]string{"Remote-User": "forged"}); rr.Code != http.StatusOK || seen != "" {
		t.Fatalf("public carve-out: code=%d Remote-User=%q, want 200 and no forged header", rr.Code, seen)
	}
	if rr := req(e, "GET", "fa.test", "/app", "203.0.113.9", map[string]string{"Remote-User": "forged"}); rr.Code != http.StatusOK || seen != "real-user" {
		t.Fatalf("gated path: code=%d Remote-User=%q, want 200 and the auth server value", rr.Code, seen)
	}
}
