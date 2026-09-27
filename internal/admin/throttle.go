package admin

import (
	"strings"
	"sync"
	"time"
)

// Failed-login throttling for the admin API. The flat delay on a wrong
// password costs an attacker nothing in parallel, and the second factor is
// only six digits: without a cap, someone holding the password can walk the
// whole TOTP space. Failures are counted twice over: per client address, and
// per account (the lowercased e-mail), so that rotating through addresses (an
// IPv6 /64 is a lot of them) does not buy more attempts. Either counter
// crossing the threshold locks its key out. The re-authentication endpoints
// (password change, e-mail change, second factor, break-glass devices, the
// WireGuard key reset) feed the account counter too.

const (
	loginMaxFails   = 10
	loginWindow     = 15 * time.Minute
	loginLockout    = 15 * time.Minute
	loginSweepEvery = 500
	// loginFailDelay is the deadline every refused login answers at, measured
	// from the start of the request. bcrypt on a known account, the stand-in
	// compare on an unknown one and a wrong code all end at the same moment,
	// so the answer's timing says nothing about which it was.
	loginFailDelay = 400 * time.Millisecond
	// oidcStartMax is how many SSO sign-ins one address may start per window
	// before it is locked out: each start is a discovery and an entry in the
	// pending table.
	oidcStartMax = 30
)

type failCounter struct {
	count int
	first time.Time
	until time.Time // non-zero while locked out
}

// locked reports whether the key is locked out at now.
func (f *failCounter) locked(now time.Time) bool {
	return !f.until.IsZero() && now.Before(f.until)
}

// loginMaxTracked caps the keys a throttle tracks. At the cap an entry that is
// not locked out is dropped to make room; a locked-out entry never is, because
// dropping it would end the lockout early. A variable so tests can use a small
// cap.
var loginMaxTracked = 65536

type loginThrottle struct {
	mu     sync.Mutex
	max    int // failures per window before the key is locked out
	fails  map[string]*failCounter
	writes int
}

// newLoginThrottle makes a throttle with the login threshold.
func newLoginThrottle() *loginThrottle { return newThrottle(loginMaxFails) }

// newThrottle makes a throttle that locks a key out after max failures in a
// window.
func newThrottle(max int) *loginThrottle {
	return &loginThrottle{max: max, fails: map[string]*failCounter{}}
}

// allow reports whether this key may attempt a login right now.
func (t *loginThrottle) allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.fails[key]
	if !ok {
		return true
	}
	now := time.Now()
	if f.locked(now) {
		return false
	}
	if now.Sub(f.first) > loginWindow {
		delete(t.fails, key)
	}
	return true
}

// fail records one failed attempt, locking the key out at the threshold.
func (t *loginThrottle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	f, ok := t.fails[key]
	if !ok || (now.Sub(f.first) > loginWindow && !f.locked(now)) {
		if !ok && !t.makeRoom(now) {
			// Every tracked key is locked out: there is no room for a new
			// counter without ending someone's lockout, so this failure is
			// not tracked. The other counter (address or account) still is.
			return
		}
		t.fails[key] = &failCounter{count: 1, first: now}
	} else {
		f.count++
		if f.count >= t.max {
			f.until = now.Add(loginLockout)
		}
	}
	// Occasional sweep keeps the map from growing under a spray attack.
	if t.writes++; t.writes%loginSweepEvery == 0 {
		for k, v := range t.fails {
			if now.Sub(v.first) > loginWindow && !v.locked(now) {
				delete(t.fails, k)
			}
		}
	}
}

// makeRoom frees a slot when the table is full, preferring an entry whose
// window has passed and never taking one that is locked out. It reports
// whether there is room. Caller holds t.mu.
func (t *loginThrottle) makeRoom(now time.Time) bool {
	if len(t.fails) < loginMaxTracked {
		return true
	}
	victim := ""
	for k, f := range t.fails {
		if f.locked(now) {
			continue
		}
		victim = k
		if now.Sub(f.first) > loginWindow {
			break
		}
	}
	if victim == "" {
		return false
	}
	delete(t.fails, victim)
	return true
}

// succeed clears the counter after a successful login.
func (t *loginThrottle) succeed(key string) {
	t.mu.Lock()
	delete(t.fails, key)
	t.mu.Unlock()
}

// accountKey is the per-account throttle key for an address as typed at login:
// the same account however it is spelled.
func accountKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
