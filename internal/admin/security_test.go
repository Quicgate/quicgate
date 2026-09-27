package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
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
	put.Header.Set("Origin", "http://"+put.Host)
	put.AddCookie(&http.Cookie{Name: "qg_session", Value: sess})
	s.Handler().ServeHTTP(rr, put)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("oidc_client_secret", ""); got != "real-secret" {
		t.Fatalf("stored secret is now %q, want it preserved", got)
	}
}

// A locked-out address is refused before any password or code is checked,
// every account from it; an IPv6 client is one network (its /64), so rotating
// through its addresses does not buy more guesses. Wrong passwords do not lock
// the account itself: the right password from another network still works,
// or anyone who knows the address could keep the administrator out.
func TestLoginThrottleLocksOutAfterRepeatedFailures(t *testing.T) {
	s := newTestServer(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err := s.store.CreateUser("admin@example.com", string(hash), false); err != nil {
		t.Fatal(err)
	}
	mustUser(t, s, "other@example.com", "another-horse")
	attempt := func(addr, email, pw string) int {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"email":"`+email+`","password":"`+pw+`"}`))
		r.RemoteAddr = addr + ":5000"
		s.Handler().ServeHTTP(rr, r)
		return rr.Code
	}
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt("203.0.113.9", "admin@example.com", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	if code := attempt("203.0.113.9", "admin@example.com", "wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("after lockout: got %d, want 429", code)
	}
	// Even the correct password is refused while locked out.
	if code := attempt("203.0.113.9", "admin@example.com", "correct-horse"); code != http.StatusTooManyRequests {
		t.Fatalf("correct password while locked out: got %d, want 429", code)
	}
	// The address is locked: another account from it is refused too.
	if code := attempt("203.0.113.9", "other@example.com", "another-horse"); code != http.StatusTooManyRequests {
		t.Fatalf("another account from the locked address: got %d, want 429", code)
	}
	// The account is not locked by wrong passwords: its owner, elsewhere,
	// signs in with the right one, however the address is spelled.
	if code := attempt("198.51.100.7", "Admin@Example.com", "correct-horse"); code != http.StatusOK {
		t.Fatalf("the owner from another address after a stranger's wrong passwords: got %d, want 200", code)
	}

	// Rotating through one IPv6 /64 is one client.
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt(fmt.Sprintf("[2001:db8:1:2::%x]", i+1), "admin@example.com", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("IPv6 attempt %d: got %d, want 401", i+1, code)
		}
	}
	if code := attempt("[2001:db8:1:2:ffff::9]", "admin@example.com", "correct-horse"); code != http.StatusTooManyRequests {
		t.Fatalf("a fresh address in the locked /64: got %d, want 429", code)
	}
	if code := attempt("[2001:db8:1:3::1]", "admin@example.com", "correct-horse"); code != http.StatusOK {
		t.Fatalf("another /64: got %d, want 200", code)
	}
}

// Wrong second-factor codes lock the account's code step from every address:
// six digits are guessable fast, and whoever gets this far has the password.
// The lock is the account's alone, and the password step still answers.
func TestWrongCodesLockTheAccountsSecondFactor(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "correct-horse")
	mustUser(t, s, "other@example.com", "another-horse")
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.store.GetUserByEmail("admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetTOTPSecret(u.ID, key.Secret()); err != nil {
		t.Fatal(err)
	}
	attempt := func(addr, email, pw, code string) int {
		body, _ := json.Marshal(map[string]string{"email": email, "password": pw, "code": code})
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		r.RemoteAddr = addr + ":5000"
		s.Handler().ServeHTTP(rr, r)
		return rr.Code
	}
	// A stranger's wrong passwords, from many addresses, do not touch the
	// code step: the owner still signs in with password and code.
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt(fmt.Sprintf("192.0.2.%d", i+1), "admin@example.com", "wrong", "000000"); code != http.StatusUnauthorized {
			t.Fatalf("stranger's wrong password %d: got %d, want 401", i+1, code)
		}
	}
	first, _ := totp.GenerateCode(key.Secret(), time.Now().Add(-30*time.Second))
	if code := attempt("198.51.100.8", "admin@example.com", "correct-horse", first); code != http.StatusOK {
		t.Fatalf("the owner after a stranger's wrong passwords: got %d, want 200", code)
	}
	// One guess per address, from as many addresses as it takes.
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt(fmt.Sprintf("203.0.113.%d", i+1), "admin@example.com", "correct-horse", "000000"); code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401", i+1, code)
		}
	}
	good, _ := totp.GenerateCode(key.Secret(), time.Now())
	if code := attempt("198.51.100.7", "admin@example.com", "correct-horse", good); code != http.StatusTooManyRequests {
		t.Fatalf("the right code from a fresh address after ten wrong ones: got %d, want 429", code)
	}
	if code := attempt("198.51.100.7", "other@example.com", "another-horse", ""); code != http.StatusOK {
		t.Fatalf("another account: got %d, want 200", code)
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
