package admin

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Failed-login throttling for the admin API. The flat 400ms delay on a wrong
// password costs an attacker nothing in parallel, and the second factor is
// only six digits: without a cap, someone holding the password can walk the
// whole TOTP space. Failures are counted per client IP and the address is
// locked out once it crosses the threshold.

const (
	loginMaxFails   = 10
	loginWindow     = 15 * time.Minute
	loginLockout    = 15 * time.Minute
	loginSweepEvery = 500
)

type failCounter struct {
	count int
	first time.Time
	until time.Time // non-zero while locked out
}

type loginThrottle struct {
	mu     sync.Mutex
	fails  map[string]*failCounter
	writes int
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{fails: map[string]*failCounter{}}
}

// allow reports whether this address may attempt a login right now.
func (t *loginThrottle) allow(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.fails[ip]
	if !ok {
		return true
	}
	now := time.Now()
	if !f.until.IsZero() && now.Before(f.until) {
		return false
	}
	if now.Sub(f.first) > loginWindow {
		delete(t.fails, ip)
	}
	return true
}

// fail records one failed attempt, locking the address out at the threshold.
func (t *loginThrottle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	f, ok := t.fails[ip]
	if !ok || now.Sub(f.first) > loginWindow {
		t.fails[ip] = &failCounter{count: 1, first: now}
	} else {
		f.count++
		if f.count >= loginMaxFails {
			f.until = now.Add(loginLockout)
		}
	}
	// Occasional sweep keeps the map from growing under a spray attack.
	if t.writes++; t.writes%loginSweepEvery == 0 {
		for k, v := range t.fails {
			if now.Sub(v.first) > loginWindow && (v.until.IsZero() || now.After(v.until)) {
				delete(t.fails, k)
			}
		}
	}
}

// succeed clears the counter after a successful login.
func (t *loginThrottle) succeed(ip string) {
	t.mu.Lock()
	delete(t.fails, ip)
	t.mu.Unlock()
}

func requestIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
