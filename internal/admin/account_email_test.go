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

// ---- changing the address an account signs in with (issue 20) ----

func changeEmail(t *testing.T, s *Server, sess, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	return call(t, s, http.MethodPost, "/api/email", sess, map[string]string{"email": email, "password": password})
}

func loginCode(t *testing.T, s *Server, email, pw string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"Email": email, "Password": pw})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.77:4000" // its own throttle bucket
	s.Handler().ServeHTTP(rr, req)
	return rr.Code
}

// The default admin can take a real address: the new one signs in, the old
// one no longer does, and the profile shows the new one.
func TestEmailChangeRenamesTheAccount(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	rr := changeEmail(t, s, sess, "  Me@Example.ORG ", "password-123")
	if rr.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}
	var out struct{ Email string }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Email != "me@example.org" {
		t.Fatalf("answer email = %q, want the normalised me@example.org", out.Email)
	}
	fresh := sessionFrom(rr)
	if fresh == "" {
		t.Fatal("the change gave the caller no fresh session")
	}
	me := call(t, s, http.MethodGet, "/api/me", fresh, nil)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"email":"me@example.org"`) {
		t.Fatalf("profile after the change: %d %s", me.Code, me.Body.String())
	}
	if code := loginCode(t, s, "admin@example.com", "password-123"); code == http.StatusOK {
		t.Fatal("the old address still signs in")
	}
	login(t, s, "me@example.org", "password-123")
}

// Sessions carry the address they signed in with, so every session of the
// account ends; another account's session is left alone.
func TestEmailChangeEndsTheAccountsOtherSessions(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	mustUser(t, s, "other@example.org", "password-456")
	sess := login(t, s, "admin@example.com", "password-123")
	second := login(t, s, "admin@example.com", "password-123")
	bystander := login(t, s, "other@example.org", "password-456")

	if rr := changeEmail(t, s, sess, "me@example.org", "password-123"); rr.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}
	for name, c := range map[string]string{"the caller's old session": sess, "a second session": second} {
		if code := call(t, s, http.MethodGet, "/api/hosts", c, nil).Code; code != http.StatusUnauthorized {
			t.Errorf("%s still works after the change: %d", name, code)
		}
	}
	if code := call(t, s, http.MethodGet, "/api/hosts", bystander, nil).Code; code != http.StatusOK {
		t.Errorf("another account's session ended: %d", code)
	}
}

// The address is also what admin sign-in through an identity provider matches
// on, so a session alone must not change it.
func TestEmailChangeNeedsTheCurrentPassword(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	for name, pw := range map[string]string{"no password": "", "wrong password": "password-124"} {
		if rr := changeEmail(t, s, sess, "me@example.org", pw); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s, want 401", name, rr.Code, rr.Body.String())
		}
	}
	if code := call(t, s, http.MethodGet, "/api/hosts", sess, nil).Code; code != http.StatusOK {
		t.Fatalf("a refused change ended the session: %d", code)
	}
	login(t, s, "admin@example.com", "password-123")
}

func TestEmailChangeRefusesAnAddressInUse(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	mustUser(t, s, "taken@example.org", "password-456")
	sess := login(t, s, "admin@example.com", "password-123")

	if rr := changeEmail(t, s, sess, "Taken@example.org", "password-123"); rr.Code != http.StatusConflict {
		t.Fatalf("taken address: %d %s, want 409", rr.Code, rr.Body.String())
	}
	login(t, s, "admin@example.com", "password-123")
	login(t, s, "taken@example.org", "password-456")
}

// Only one plain address is accepted, and nothing that could pass for the
// marker of a directory, identity provider or API token session.
func TestEmailChangeRefusesWhatIsNotOneAddress(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	for name, bad := range map[string]string{
		"empty":              "",
		"no at sign":         "not-an-address",
		"display name":       "Me <me@example.org>",
		"two addresses":      "me@example.org, you@example.org",
		"oidc marker":        "oidc:me@example.org",
		"ldap marker":        "ldap:me@example.org",
		"api token marker":   "api-token",
		"longer than 254":    strings.Repeat("a", 250) + "@example.org",
		"space in the local": "me you@example.org",
	} {
		if rr := changeEmail(t, s, sess, bad, "password-123"); rr.Code != http.StatusBadRequest {
			t.Errorf("%s (%q): %d %s, want 400", name, bad, rr.Code, rr.Body.String())
		}
	}
	login(t, s, "admin@example.com", "password-123")
}

// The second factor is sealed to the account's row, not its address, so it
// is still asked for (and still accepted) after the change.
func TestEmailChangeKeepsTheSecondFactor(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
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
	if rr := changeEmail(t, s, sess, "me@example.org", "password-123"); rr.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}

	body, _ := json.Marshal(map[string]string{"Email": "me@example.org", "Password": "password-123"})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if !strings.Contains(rr.Body.String(), `"totpRequired":true`) {
		t.Fatalf("sign-in under the new address did not ask for the second factor: %d %s", rr.Code, rr.Body.String())
	}
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	body, _ = json.Marshal(map[string]string{"Email": "me@example.org", "Password": "password-123", "Code": code})
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK || sessionFrom(rr) == "" {
		t.Fatalf("the second factor no longer opens after the change: %d %s", rr.Code, rr.Body.String())
	}
}

// An API token has no account behind it to rename.
func TestEmailChangeByAPITokenIsRefused(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	tok, err := s.store.CreateAPIToken("automation")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"email": "me@example.org", "password": "password-123"})
	req := httptest.NewRequest(http.MethodPost, "/api/email", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("API token change: %d %s, want 400", rr.Code, rr.Body.String())
	}
	login(t, s, "admin@example.com", "password-123")
}

// A login that verified the password under the old address, and is still on
// its way to a session when the address changes, gets no working session: it
// only stores one while the account it verified is still found unchanged.
func TestLoginRacingEmailChangeGetsNoSession(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	current := login(t, s, "admin@example.com", "password-123")

	reached, release := make(chan struct{}), make(chan struct{})
	testHookLoginVerified = func() { close(reached); <-release }
	defer func() { testHookLoginVerified = nil }()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "password-123"})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
		done <- rr
	}()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the login never reached the verified state")
	}
	if rr := changeEmail(t, s, current, "me@example.org", "password-123"); rr.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}
	close(release)
	stale := <-done
	if c := sessionFrom(stale); c != "" && call(t, s, http.MethodGet, "/api/hosts", c, nil).Code == http.StatusOK {
		t.Fatal("a login verified under the old address got a working session after the change")
	}
}
