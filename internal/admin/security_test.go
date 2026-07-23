package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "quicgate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, nil, nil, t.TempDir())
}

func TestMetricsRequiresAuth(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestCSRFFilterBlocksCrossSiteCookieWrites(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.Host = "admin.example.test"
	req.Header.Set("Origin", "https://evil.example.test")
	req.AddCookie(&http.Cookie{Name: "qg_session", Value: "deadbeef"})
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site cookie POST status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestMustChangeSessionCannotUseManagementAPIs(t *testing.T) {
	s := newTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := s.store.CreateUser("admin@example.com", string(hash), true); err != nil {
		t.Fatalf("create user: %v", err)
	}

	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"Email":"admin@example.com","Password":"changeme"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d", login.Code, http.StatusOK)
	}
	cookies := login.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("must-change /api/hosts status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestSecurityHeadersAreApplied(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-methods", nil))
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q, want frame-ancestors restriction", got)
	}
}
