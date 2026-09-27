package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// The stand-in hash for unknown accounts must be a real hash at the stored
// cost (M-5): bcrypt refuses a malformed one before doing any work, which is
// what made the old comparison a no-op.
func TestDummyHashIsARealHashAtTheStoredCost(t *testing.T) {
	cost, err := bcrypt.Cost([]byte(dummyHash))
	if err != nil || cost != bcrypt.DefaultCost {
		t.Fatalf("dummy hash cost = %d (%v), want %d", cost, err, bcrypt.DefaultCost)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte("guess")); err != bcrypt.ErrMismatchedHashAndPassword {
		t.Fatalf("compare against the dummy hash = %v, want a plain mismatch", err)
	}
}

// A full throttle table never drops a locked-out entry to make room (M-2):
// that would end the lockout early. Unlocked entries are what makes room.
func TestLoginThrottleKeepsLockoutsWhenFull(t *testing.T) {
	old := loginMaxTracked
	loginMaxTracked = 2
	t.Cleanup(func() { loginMaxTracked = old })

	th := newLoginThrottle()
	for _, key := range []string{"locked-a", "locked-b"} {
		for i := 0; i < loginMaxFails; i++ {
			th.fail(key)
		}
		if th.allow(key) {
			t.Fatalf("%s is not locked out after %d failures", key, loginMaxFails)
		}
	}
	for i := 0; i < 5; i++ {
		th.fail(fmt.Sprintf("newcomer-%d", i))
	}
	for _, key := range []string{"locked-a", "locked-b"} {
		if th.allow(key) {
			t.Fatalf("%s's lockout was dropped to make room", key)
		}
	}
	if n := len(th.fails); n > 2 {
		t.Fatalf("throttle tracks %d keys, cap is 2", n)
	}
	// Once an entry is unlocked, it is the one that goes.
	th.succeed("locked-b")
	th.fail("fresh")
	th.fail("another")
	if th.allow("locked-a") {
		t.Fatal("the remaining lockout was dropped although an unlocked entry could go")
	}
	if _, ok := th.fails["fresh"]; ok {
		t.Fatal("the unlocked entry stayed while the table was full")
	}
	if _, ok := th.fails["another"]; !ok {
		t.Fatal("the new failure was not tracked although an unlocked entry could go")
	}
}

// Every refused login runs one bcrypt compare, against the account's hash or
// the stand-in, and answers at the same deadline (M-5, M-2): neither the
// timing nor the presence of a delay says whether the account exists, and a
// wrong second-factor code is delayed the same way.
func TestLoginFailuresCostTheSameForKnownAndUnknownAccounts(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	var compares atomic.Int32
	real := bcryptCompare
	const inCompare = 200 * time.Millisecond
	bcryptCompare = func(hash, pw []byte) error {
		compares.Add(1)
		// Stands in for bcrypt's cost, made the same on every path and large
		// enough to see: the real compare at cost 10 takes longer than the
		// deadline under the race detector, which would hide what this test
		// is about. (That the stand-in hash is a real one is checked above.)
		time.Sleep(inCompare)
		if string(hash) == dummyHash {
			return bcrypt.ErrMismatchedHashAndPassword
		}
		return real(hash, pw) // the test account's hash is at the minimum cost
	}
	t.Cleanup(func() { bcryptCompare = real })

	attempt := func(email, pw, code string) (int, time.Duration) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"Email": email, "Password": pw, "Code": code})
		rr := httptest.NewRecorder()
		start := time.Now()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
		return rr.Code, time.Since(start)
	}
	check := func(what string, code int, took time.Duration, wantCompares int32) {
		t.Helper()
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", what, code)
		}
		if n := compares.Load(); n != wantCompares {
			t.Fatalf("%s: %d bcrypt compares so far, want %d", what, n, wantCompares)
		}
		// At the deadline: not before it, and not the deadline on top of the
		// compare (which is what an additive sleep would give).
		if took < loginFailDelay || took >= loginFailDelay+inCompare-20*time.Millisecond {
			t.Fatalf("%s took %v, want about %v: a deadline, not a delay added to the compare", what, took, loginFailDelay)
		}
	}
	code, took := attempt("nobody@example.com", "whatever", "")
	check("unknown account", code, took, 1)
	code, took = attempt("admin@example.com", "wrong-password", "")
	check("known account, wrong password", code, took, 2)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.store.GetUserByEmail("admin@example.com")
	if err := s.store.SetTOTPSecret(u.ID, key.Secret()); err != nil {
		t.Fatal(err)
	}
	right, _ := totp.GenerateCode(key.Secret(), time.Now())
	wrong := "9" + right[1:]
	if right[0] == '9' {
		wrong = "0" + right[1:]
	}
	code, took = attempt("admin@example.com", "password-123", wrong)
	check("known account, wrong code", code, took, 3)
}

// Failed re-authentications (the password confirmation for a change to the
// account's own protection) count against the account like failed logins
// (L-2): a stolen session cannot guess the password at leisure, and the
// lockout covers signing in as well.
func TestReauthenticationFailuresLockTheAccount(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	for i := 0; i < loginMaxFails; i++ {
		if rr := call(t, s, http.MethodPost, "/api/2fa/disable", sess, map[string]string{"Password": "wrong"}); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %s, want 401", i+1, rr.Code, rr.Body.String())
		}
	}
	if rr := call(t, s, http.MethodPost, "/api/2fa/disable", sess, map[string]string{"Password": "password-123"}); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures, the right password: %d %s, want 429", loginMaxFails, rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, "/api/password", sess, map[string]string{"Current": "password-123", "New": "password-456"}); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("password change while locked: %d %s, want 429", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, "/api/email", sess, map[string]string{"email": "me@example.org", "password": "password-123"}); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("email change while locked: %d %s, want 429", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/server-key/reset", sess, map[string]string{"password": "password-123"}); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("key reset while locked: %d %s, want 429", rr.Code, rr.Body.String())
	}
	if code := loginCode(t, s, "admin@example.com", "password-123"); code != http.StatusTooManyRequests {
		t.Fatalf("login while the account is locked: %d, want 429", code)
	}
}

// A password over bcrypt's 72-byte limit is refused as a bad request, in so
// many words, wherever a password is taken (STO-16); it used to surface as a
// 500 or as a plain mismatch.
func TestOverlongPasswordsAreRefusedAsBadRequests(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	long := strings.Repeat("p", maxPasswordBytes+1)
	body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": long})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "72 bytes") {
		t.Fatalf("login with a %d-byte password: %d %s, want 400 naming the limit", len(long), rr.Code, rr.Body.String())
	}
	for name, body := range map[string]map[string]string{
		"new password too long":     {"Current": "password-123", "New": long},
		"current password too long": {"Current": long, "New": "password-456"},
	} {
		if rr := call(t, s, http.MethodPost, "/api/password", sess, body); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "72 bytes") {
			t.Errorf("%s: %d %s, want 400 naming the limit", name, rr.Code, rr.Body.String())
		}
	}
	if rr := call(t, s, http.MethodPost, "/api/email", sess, map[string]string{"email": "me@example.org", "password": long}); rr.Code != http.StatusBadRequest {
		t.Errorf("email change with an overlong password: %d %s, want 400", rr.Code, rr.Body.String())
	}
	// The account is untouched and still signs in.
	login(t, s, "admin@example.com", "password-123")
}
