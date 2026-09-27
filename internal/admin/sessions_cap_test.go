package admin

import (
	"net/http"
	"testing"
	"time"
)

// Expired sessions are swept when a session is created, and one account holds
// at most maxSessionsPerAccount live sessions, the oldest ending when another
// starts (ADM-16); another account's sessions are left alone.
func TestSessionsAreSweptAndCappedPerAccount(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	mustUser(t, s, "other@example.com", "password-456")
	u, err := s.store.GetUserByEmail("admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.sessions["stale"] = session{userID: u.ID, email: u.Email, expires: time.Now().Add(-time.Minute)}
	bystander := login(t, s, "other@example.com", "password-456")
	if _, ok := s.sessions["stale"]; ok {
		t.Fatal("an expired session survived a login")
	}

	first := login(t, s, "admin@example.com", "password-123")
	var last string
	for i := 1; i <= maxSessionsPerAccount; i++ {
		last = login(t, s, "admin@example.com", "password-123")
	}
	s.mu.Lock()
	n := 0
	for _, v := range s.sessions {
		if v.userID == u.ID {
			n++
		}
	}
	s.mu.Unlock()
	if n != maxSessionsPerAccount {
		t.Fatalf("%d live sessions for the account after %d logins, want the cap of %d", n, maxSessionsPerAccount+1, maxSessionsPerAccount)
	}
	if code := call(t, s, http.MethodGet, "/api/hosts", first, nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("the oldest session survived the cap: %d", code)
	}
	if code := call(t, s, http.MethodGet, "/api/hosts", last, nil).Code; code != http.StatusOK {
		t.Fatalf("the newest session: %d, want 200", code)
	}
	if code := call(t, s, http.MethodGet, "/api/hosts", bystander, nil).Code; code != http.StatusOK {
		t.Fatalf("another account's session was evicted: %d", code)
	}
}
