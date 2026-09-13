package admin

import (
	"fmt"
	"net/http"
	"testing"
)

func TestLoginThrottleTrackingCap(t *testing.T) {
	old := loginMaxTracked
	loginMaxTracked = 3
	t.Cleanup(func() { loginMaxTracked = old })

	th := newLoginThrottle()
	for i := 0; i < 10; i++ {
		th.fail(fmt.Sprintf("198.51.100.%d", i))
	}
	if n := len(th.fails); n > 3 {
		t.Fatalf("login throttle tracks %d addresses, cap is 3", n)
	}
}

// Q11: an explicit sign-out of every other admin session.
func TestRevokeOtherAdminSessions(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	a := login(t, s, "admin@example.com", "password-123")
	b := login(t, s, "admin@example.com", "password-123")
	c := login(t, s, "admin@example.com", "password-123")

	if rr := call(t, s, http.MethodPost, "/api/sessions/revoke", a, nil); rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	for name, sess := range map[string]string{"b": b, "c": c} {
		if got := call(t, s, http.MethodGet, "/api/hosts", sess, nil).Code; got != http.StatusUnauthorized {
			t.Fatalf("session %s after revoke-others: got %d, want 401", name, got)
		}
	}
	if got := call(t, s, http.MethodGet, "/api/hosts", a, nil).Code; got != http.StatusOK {
		t.Fatalf("the revoking session: got %d, want 200", got)
	}
}

// Q10/Q11: a restore replaces users, passwords and tokens, so every session
// that existed before it ends.
func TestRestoreRevokesSessions(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	other := login(t, s, "admin@example.com", "password-123")
	archive := backupArchive(t, s, sess)

	if rr := call(t, s, http.MethodPost, "/api/restore", sess, archive); rr.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rr.Code, rr.Body.String())
	}
	for name, v := range map[string]string{"restoring": sess, "other": other} {
		if got := call(t, s, http.MethodGet, "/api/hosts", v, nil).Code; got != http.StatusUnauthorized {
			t.Fatalf("%s session after restore: got %d, want 401", name, got)
		}
	}
}

// Q11: signing everyone out of SSO rotates the cookie signing key.
func TestRevokeSSOSessionsRotatesKey(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	const old = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := s.store.SetSetting("sso_cookie_secret", old); err != nil {
		t.Fatal(err)
	}
	if rr := call(t, s, http.MethodPost, "/api/sso/revoke-sessions", sess, nil); rr.Code != http.StatusOK {
		t.Fatalf("revoke SSO sessions: %d %s", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("sso_cookie_secret", ""); got == old {
		t.Fatal("the SSO signing key is unchanged after signing everyone out")
	}
}
