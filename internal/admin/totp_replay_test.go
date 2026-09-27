package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// A code opens the account once (L-1). Within its window a second use is
// refused, as is any code of a step no later than the last one accepted; the
// next step's code works.
func TestTOTPCodeIsGoodOnce(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
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
	base := time.Now()
	totpNow = func() time.Time { return base }
	t.Cleanup(func() { totpNow = time.Now })
	attempt := func(at time.Time) int {
		t.Helper()
		code, err := totp.GenerateCode(key.Secret(), at)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "password-123", "Code": code})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
		return rr.Code
	}
	if code := attempt(base); code != http.StatusOK {
		t.Fatalf("first use of the code: %d, want 200", code)
	}
	if code := attempt(base); code != http.StatusUnauthorized {
		t.Fatalf("the same code opened the account twice: %d", code)
	}
	if code := attempt(base.Add(-totpPeriod * time.Second)); code != http.StatusUnauthorized {
		t.Fatalf("the previous step's code, inside the window but before the accepted step: %d, want 401", code)
	}
	if code := attempt(base.Add(totpPeriod * time.Second)); code != http.StatusOK {
		t.Fatalf("the next step's code: %d, want 200", code)
	}
	if u, _ := s.store.GetUserByEmail("admin@example.com"); u.TOTPLast != base.Unix()/totpPeriod+1 {
		t.Fatalf("recorded step = %d, want %d", u.TOTPLast, base.Unix()/totpPeriod+1)
	}
}

// The secret 2FA enable confirms is the one setup bound to the session (L-3):
// a secret the client sends is not used, enable without setup is refused, the
// confirming code is spent, and an API token has no session to set up for.
func TestTOTPEnableUsesTheSecretFromSetup(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	if rr := call(t, s, http.MethodPost, "/api/2fa/enable", sess, map[string]string{"Code": "123456", "Password": "password-123"}); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "setup") {
		t.Fatalf("enable without setup: %d %s, want 400 pointing at the setup step", rr.Code, rr.Body.String())
	}
	secret := setup2FA(t, s, sess)
	base := time.Now()
	totpNow = func() time.Time { return base }
	t.Cleanup(func() { totpNow = time.Now })

	other, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(other.Secret(), base)
	if rr := call(t, s, http.MethodPost, "/api/2fa/enable", sess, map[string]string{"Secret": other.Secret(), "Code": code, "Password": "password-123"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("enable with a client-supplied secret: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if u, _ := s.store.GetUserByEmail("admin@example.com"); u.TOTPSecret != "" {
		t.Fatal("a client-supplied secret was stored")
	}

	code, _ = totp.GenerateCode(secret, base)
	if rr := call(t, s, http.MethodPost, "/api/2fa/enable", sess, map[string]string{"Code": code, "Password": "password-123"}); rr.Code != http.StatusOK {
		t.Fatalf("enable with the setup secret's code: %d %s", rr.Code, rr.Body.String())
	}
	if u, _ := s.store.GetUserByEmail("admin@example.com"); u.TOTPSecret != secret {
		t.Fatal("the stored secret is not the one setup bound to the session")
	}
	// The confirming code is spent: it does not sign in, the next one does.
	loginWith := func(code string) int {
		body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "password-123", "Code": code})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
		return rr.Code
	}
	if got := loginWith(code); got != http.StatusUnauthorized {
		t.Fatalf("signing in with the code that enabled 2FA: %d, want 401", got)
	}
	next, _ := totp.GenerateCode(secret, base.Add(totpPeriod*time.Second))
	if got := loginWith(next); got != http.StatusOK {
		t.Fatalf("signing in with the next code: %d, want 200", got)
	}

	tok, err := s.store.CreateAPIToken("automation")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/2fa/setup", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("2FA setup by an API token: %d %s, want 400", rr.Code, rr.Body.String())
	}
}
