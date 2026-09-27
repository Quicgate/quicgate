package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// Selecting an identity provider for admin sign-in is the whole configuration
// (F-6): the login works without the separate switch and without an explicit
// redirect URL, which is derived from the request, with the scheme believed
// only from a trusted proxy. The explicit setting still wins.
func TestAdminOIDCWorksWithOnlyASelectedProvider(t *testing.T) {
	s := newTestServer(t)
	idp := newAdminIdP(t)
	idp.email = "boss@example.com"
	p := store.OIDCProvider{Name: "corp", Issuer: idp.srv.URL, ClientID: "admin-client", ClientSecret: "s"}
	if err := s.store.CreateOIDCProvider(&p); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"admin_oidc_provider_id": fmt.Sprint(p.ID), "oidc_allowed_emails": "boss@example.com"} {
		if err := s.store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-methods", nil))
	if !strings.Contains(rr.Body.String(), `"oidc":true`) {
		t.Fatalf("auth-methods with a selected provider: %s, want oidc on", rr.Body.String())
	}
	start := func(host, proto string) (*httptest.ResponseRecorder, *url.URL) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
		req.Host = host
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("login with only a provider selected: %d %s", rr.Code, rr.Body.String())
		}
		loc, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return rr, loc
	}
	// From an untrusted peer, X-Forwarded-Proto is not believed.
	if _, loc := start("admin.example.test", "https"); loc.Query().Get("redirect_uri") != "http://admin.example.test/api/oidc/callback" {
		t.Fatalf("derived redirect URL = %q, want http://admin.example.test/api/oidc/callback", loc.Query().Get("redirect_uri"))
	}
	// Behind a trusted proxy the scheme it states is.
	for k, v := range map[string]string{"trusted_proxies": "192.0.2.1", "real_ip_header": "X-Forwarded-For"} {
		if err := s.store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	s.loadClientIP()
	rr, loc := start("admin.example.test", "https")
	if got := loc.Query().Get("redirect_uri"); got != "https://admin.example.test/api/oidc/callback" {
		t.Fatalf("derived redirect URL behind a trusted proxy = %q, want https", got)
	}
	// The whole sign-in works that way.
	idp.nonce, idp.challenge = loc.Query().Get("nonce"), loc.Query().Get("code_challenge")
	if cb := adminCallback(s, loc.Query().Get("state"), rr.Result().Cookies()); cb.Code != http.StatusFound || sessionFrom(cb) == "" {
		t.Fatalf("callback: %d %s, want a session", cb.Code, cb.Body.String())
	}
	// An explicit redirect URL still wins.
	if err := s.store.SetSetting("oidc_redirect_url", "https://admin.test/api/oidc/callback"); err != nil {
		t.Fatal(err)
	}
	if _, loc := start("admin.example.test", "https"); loc.Query().Get("redirect_uri") != "https://admin.test/api/oidc/callback" {
		t.Fatalf("explicit redirect URL not used: %q", loc.Query().Get("redirect_uri"))
	}
}

// Discovery is fetched once per issuer and reused, and sign-in starts are
// counted per client address (L-4): the endpoint is unauthenticated.
func TestAdminOIDCDiscoveryIsCachedAndStartsAreRateLimited(t *testing.T) {
	s, idp := adminOIDCServer(t)
	startAdminOIDC(t, s)
	startAdminOIDC(t, s)
	if n := idp.discoveries.Load(); n != 1 {
		t.Fatalf("discovery was fetched %d times for two sign-ins, want once", n)
	}
	for i := 2; i < oidcStartMax; i++ {
		startAdminOIDC(t, s)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("sign-in start %d from one address: %d, want 429", oidcStartMax+1, rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	req.RemoteAddr = "198.51.100.7:1"
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("sign-in start from another address: %d, want 302", rr.Code)
	}
}

// A full table of pending sign-ins refuses the new one rather than dropping a
// live one (L-4): whoever is in the middle of signing in must be able to
// finish.
func TestAdminOIDCFullPendingTableRefusesNewSignIns(t *testing.T) {
	old := adminOIDCMaxPending
	adminOIDCMaxPending = 2
	t.Cleanup(func() { adminOIDCMaxPending = old })
	s, idp := adminOIDCServer(t)
	idp.email = "boss@example.com"
	first, loc := startAdminOIDC(t, s)
	startAdminOIDC(t, s)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("third sign-in with a table of two: %d %s, want 503", rr.Code, rr.Body.String())
	}
	// The first sign-in is still live and completes.
	idp.nonce, idp.challenge = loc.Query().Get("nonce"), loc.Query().Get("code_challenge")
	if cb := adminCallback(s, loc.Query().Get("state"), first.Result().Cookies()); cb.Code != http.StatusFound || sessionFrom(cb) == "" {
		t.Fatalf("the first sign-in was dropped: %d %s", cb.Code, cb.Body.String())
	}
}

// What the IdP answers, or why it cannot be reached, is for the server log,
// not for whoever hit the unauthenticated endpoints (L-4).
func TestAdminOIDCDoesNotEchoIdPErrors(t *testing.T) {
	s, idp := adminOIDCServer(t)
	idp.tokenError = `{"error":"invalid_client","error_description":"SECRET-IDP-DIAGNOSTIC-7731"}`
	rr, loc := startAdminOIDC(t, s)
	cb := adminCallback(s, loc.Query().Get("state"), rr.Result().Cookies())
	if cb.Code == http.StatusFound || sessionFrom(cb) != "" {
		t.Fatalf("a failed token exchange minted a session (%d)", cb.Code)
	}
	if strings.Contains(cb.Body.String(), "SECRET-IDP-DIAGNOSTIC") {
		t.Fatalf("the IdP's error body is echoed: %s", cb.Body.String())
	}

	unreachable := newTestServer(t)
	for k, v := range map[string]string{
		"oidc_enabled": "1", "oidc_issuer": "http://127.0.0.1:9/UNIQUE-ISSUER-PATH", "oidc_client_id": "c",
		"oidc_redirect_url": "https://admin.test/api/oidc/callback",
	} {
		if err := unreachable.store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	rr = httptest.NewRecorder()
	unreachable.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil))
	if rr.Code != http.StatusBadGateway || strings.Contains(rr.Body.String(), "UNIQUE-ISSUER-PATH") {
		t.Fatalf("login against an unreachable issuer: %d %s, want 502 without the issuer's details", rr.Code, rr.Body.String())
	}
}
