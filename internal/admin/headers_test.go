package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"quicgate/internal/engine"
	"quicgate/internal/store"
)

// API answers and metrics are never cacheable (L-5): they carry settings,
// tokens, second-factor secrets and backups.
func TestAPIResponsesAreNotCacheable(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/api/auth-methods", "/api/version", "/metrics", "/api/hosts", "/api/backup"} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, cc)
		}
		if p := rr.Header().Get("Pragma"); p != "no-cache" {
			t.Errorf("%s: Pragma = %q, want no-cache", path, p)
		}
	}
}

// A cookie-authenticated write with neither Origin nor Referer is refused
// (L-7): browsers send Origin on every such request, so one without it did not
// come from a page the usual way. Bearer-token calls are unaffected.
func TestCookieWritesWithoutOriginAreRefused(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	post := func(headers map[string]string, cookie bool, bearer string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/sessions/revoke", nil)
		if cookie {
			req.AddCookie(&http.Cookie{Name: "qg_session", Value: sess})
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post(nil, true, ""); code != http.StatusForbidden {
		t.Fatalf("cookie write without Origin or Referer: %d, want 403", code)
	}
	if code := post(map[string]string{"Origin": "null"}, true, ""); code != http.StatusForbidden {
		t.Fatalf("cookie write with Origin: null: %d, want 403", code)
	}
	if code := post(map[string]string{"Referer": "http://example.com/"}, true, ""); code != http.StatusOK {
		t.Fatalf("cookie write with a same-site Referer: %d, want 200", code)
	}
	if code := post(map[string]string{"Origin": "http://example.com"}, true, ""); code != http.StatusOK {
		t.Fatalf("cookie write with a same-site Origin: %d, want 200", code)
	}
	tok, err := s.store.CreateAPIToken("automation")
	if err != nil {
		t.Fatal(err)
	}
	if code := post(nil, false, tok.Token); code != http.StatusOK {
		t.Fatalf("bearer write without Origin: %d, want 200", code)
	}
}

// The embedded UI serves files, never directory listings (L-8): the layout of
// the tree is nobody's business before signing in, while the documentation
// pages and the OpenAPI document keep working.
func TestStaticFilesServeNoDirectoryListings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New(engine.Config{DisableTLS: true, DataDir: t.TempDir()}, st)
	webFS := fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html><title>quicgate</title>")},
		"docs.html":             {Data: []byte("<title>docs</title>")},
		"openapi.yaml":          {Data: []byte("openapi: 3.0.0")},
		"docs/sso.md":           {Data: []byte("# SSO")},
		"fonts/Geist-400.woff2": {Data: []byte("wOFF")},
	}
	s := New(st, eng, webFS, t.TempDir())
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}
	for _, path := range []string{"/", "/docs.html", "/openapi.yaml", "/docs/sso.md", "/fonts/Geist-400.woff2"} {
		if rr := get(path); rr.Code != http.StatusOK {
			t.Errorf("%s: %d, want 200", path, rr.Code)
		}
	}
	if body := get("/").Body.String(); !strings.Contains(body, "quicgate") {
		t.Errorf("the root does not serve index.html: %q", body)
	}
	// (An unclean path such as /docs/../fonts/ is redirected to its clean form
	// by the mux before this handler sees it, and the clean form answers 404.)
	for _, path := range []string{"/docs/", "/docs", "/fonts/", "/fonts"} {
		if rr := get(path); rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d %q, want 404 (no listing, no redirect to one)", path, rr.Code, rr.Body.String())
		}
	}
}

// The unauthenticated version endpoint names the app version only (L-8).
func TestVersionHidesTheGoRuntime(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	var out map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("version: %d %s (%v)", rr.Code, rr.Body.String(), err)
	}
	if _, ok := out["version"]; !ok {
		t.Fatalf("no version in %s", rr.Body.String())
	}
	if _, ok := out["go"]; ok {
		t.Fatalf("the Go runtime version is exposed: %s", rr.Body.String())
	}
}

// GET /api/me with an API token says it is a token, instead of failing (F-5).
func TestProfileOfAnAPIToken(t *testing.T) {
	s := newTestServer(t)
	tok, err := s.store.CreateAPIToken("automation")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/me with a token: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Email string `json:"email"`
		Token bool   `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || !out.Token || out.Email != "" {
		t.Fatalf("/api/me with a token = %s, want a token principal with no address", rr.Body.String())
	}
}
