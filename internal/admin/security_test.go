package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/engine"
	"quicgate/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "quicgate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New(engine.Config{DisableTLS: true, DataDir: t.TempDir()}, st)
	return New(st, eng, nil, t.TempDir())
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

// Credentials for other systems must not be echoed back on a settings read,
// and sending the mask back must not wipe the stored value.
func TestSecretSettingsAreMaskedAndPreserved(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.SetSetting("oidc_client_secret", "real-secret"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting("acme_dns_config", `{"login":"x","private_key":"KEY"}`); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw12345678"), bcrypt.DefaultCost)
	if err := s.store.CreateUser("admin@example.com", string(hash), false); err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"Email":"admin@example.com","Password":"pw12345678"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", login.Code, login.Body.String())
	}
	sess := login.Result().Cookies()[0].Value

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.AddCookie(&http.Cookie{Name: "qg_session", Value: sess})
	s.Handler().ServeHTTP(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, "real-secret") || strings.Contains(body, "private_key") {
		t.Fatalf("settings read leaked a secret: %s", body)
	}
	if !strings.Contains(body, secretMask) {
		t.Fatalf("expected the mask in the response: %s", body)
	}

	// Saving other settings while echoing the mask keeps the stored secrets.
	rr = httptest.NewRecorder()
	put := httptest.NewRequest(http.MethodPut, "/api/settings",
		strings.NewReader(`{"acme_email":"a@b.c","oidc_client_secret":"`+secretMask+`"}`))
	put.Header.Set("Content-Type", "application/json")
	put.AddCookie(&http.Cookie{Name: "qg_session", Value: sess})
	s.Handler().ServeHTTP(rr, put)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("oidc_client_secret", ""); got != "real-secret" {
		t.Fatalf("stored secret is now %q, want it preserved", got)
	}
}

// A locked-out address is refused before any password or code is checked.
func TestLoginThrottleLocksOutAfterRepeatedFailures(t *testing.T) {
	s := newTestServer(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err := s.store.CreateUser("admin@example.com", string(hash), false); err != nil {
		t.Fatal(err)
	}
	attempt := func(pw string) int {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"email":"admin@example.com","password":"`+pw+`"}`))
		r.RemoteAddr = "203.0.113.9:5000"
		s.Handler().ServeHTTP(rr, r)
		return rr.Code
	}
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	if code := attempt("wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("after lockout: got %d, want 429", code)
	}
	// Even the correct password is refused while locked out.
	if code := attempt("correct-horse"); code != http.StatusTooManyRequests {
		t.Fatalf("correct password while locked out: got %d, want 429", code)
	}
	// A different address is unaffected.
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"email":"admin@example.com","password":"correct-horse"}`))
	r.RemoteAddr = "198.51.100.7:5000"
	s.Handler().ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("other address: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// An empty allow-list must not mean "anyone this IdP will authenticate": that
// hands the whole proxy to every account in someone else's tenant.
func TestExternalIdentityNeedsLocalAccountOrAllowList(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateUser("admin@example.com", "x", false); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, email, allowList string
		want                   bool
	}{
		{"local account, empty list", "admin@example.com", "", true},
		{"stranger, empty list", "attacker@evil.test", "", false},
		{"stranger, listed", "ops@example.com", "ops@example.com", true},
		{"stranger, different entry listed", "attacker@evil.test", "ops@example.com", false},
		{"case-insensitive listing", "OPS@Example.com", "ops@example.com", true},
	}
	for _, c := range cases {
		_, localErr := s.store.GetUserByEmail(c.email)
		got := localErr == nil || emailAllowed(c.email, c.allowList)
		if got != c.want {
			t.Errorf("%s: admitted=%v, want %v", c.name, got, c.want)
		}
	}
}

// The LDAP gate is authorisation, not just authentication: binding proves the
// password, the allow-list decides who may administer the proxy.
func TestLDAPIdentityApproval(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateUser("alice", "x", false); err != nil {
		t.Fatal(err)
	}
	if !s.ldapIdentityApproved("alice") {
		t.Error("a directory user with a local account should be approved")
	}
	if s.ldapIdentityApproved("mallory") {
		t.Error("an unknown directory user must not be approved by default")
	}
	if err := s.store.SetSetting("ldap_allowed_users", "bob, carol"); err != nil {
		t.Fatal(err)
	}
	if !s.ldapIdentityApproved("bob") {
		t.Error("an allow-listed directory user should be approved")
	}
	if s.ldapIdentityApproved("mallory") {
		t.Error("a user outside the allow-list must stay rejected")
	}
}

// A plaintext LDAP URL must be refused rather than sending the password in the
// clear, even when everything else is configured.
func TestLDAPRequiresTLS(t *testing.T) {
	s := newTestServer(t)
	for k, v := range map[string]string{
		"ldap_enabled": "1", "ldap_url": "ldap://ldap.example.test:389",
		"ldap_bind_dn_template": "uid=%s,ou=people,dc=example,dc=com",
	} {
		if err := s.store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if s.ldapAuth("alice", "hunter2") {
		t.Error("plaintext ldap:// bind should be refused")
	}
}

// An allow-listed external identity has no local row; the profile call must
// still work instead of 500ing.
func TestExternalIdentityProfile(t *testing.T) {
	s := newTestServer(t)
	tok := "ext-session"
	s.sessions[tok] = session{email: "oidc:ops@example.com", expires: time.Now().Add(time.Hour)}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "qg_session", Value: tok})
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/me for an external identity = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "oidc:ops@example.com") {
		t.Fatalf("profile did not report the session identity: %s", rr.Body.String())
	}
}
