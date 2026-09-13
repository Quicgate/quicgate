package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---- the admin identity provider reference fails closed ----

func TestSettingsRejectDanglingAdminOIDCProvider(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	for _, id := range []string{"999999", "not-a-number"} {
		rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"admin_oidc_provider_id": id})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("admin_oidc_provider_id=%q: got %d %s, want 400", id, rr.Code, rr.Body.String())
		}
	}
	if got := s.store.GetSetting("admin_oidc_provider_id", ""); got != "" {
		t.Fatalf("a rejected provider id was stored: %q", got)
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"admin_oidc_provider_id": ""}); rr.Code != http.StatusOK {
		t.Fatalf("clearing the provider: got %d %s, want 200", rr.Code, rr.Body.String())
	}
}

// A provider reference that no longer resolves (a restore, a hand edit) must
// not fall back to the inline issuer: the operator chose a provider, and
// signing in against a different one is not what they configured.
func TestAdminOIDCMissingProviderFailsClosed(t *testing.T) {
	s, _ := adminOIDCServer(t)
	if err := s.store.SetSetting("admin_oidc_provider_id", "999999"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusFound {
		t.Fatalf("login with a missing provider redirected to %q, want an error", rr.Header().Get("Location"))
	}
}

// ---- a login that verified the old password cannot outlive its change ----

func TestLoginRacingPasswordChangeGetsNoSession(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "old-password-1")
	current := login(t, s, "admin@example.com", "old-password-1")

	// racingLogin pauses a login between verifying the password and creating
	// its session, runs between() in that gap, and returns the login response.
	racingLogin := func(between func()) *httptest.ResponseRecorder {
		t.Helper()
		reached, release := make(chan struct{}), make(chan struct{})
		testHookLoginVerified = func() { close(reached); <-release }
		defer func() { testHookLoginVerified = nil }()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "old-password-1"})
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
			done <- rr
		}()
		select {
		case <-reached:
		case <-time.After(5 * time.Second):
			t.Fatal("the login never reached the verified state")
		}
		between()
		close(release)
		return <-done
	}

	// Control: with nothing in between, the paused login works.
	ok := racingLogin(func() {})
	if c := sessionFrom(ok); c == "" || call(t, s, http.MethodGet, "/api/hosts", c, nil).Code != http.StatusOK {
		t.Fatalf("control login did not yield a working session: %d %s", ok.Code, ok.Body.String())
	}

	stale := racingLogin(func() {
		rr := call(t, s, http.MethodPost, "/api/password", current,
			map[string]string{"current": "old-password-1", "new": "new-password-2"})
		if rr.Code != http.StatusOK {
			t.Fatalf("password change: %d %s", rr.Code, rr.Body.String())
		}
	})
	if c := sessionFrom(stale); c != "" && call(t, s, http.MethodGet, "/api/hosts", c, nil).Code == http.StatusOK {
		t.Fatal("a login verified against the old password got a working session after the password change")
	}
}
