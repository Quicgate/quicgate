package engine

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// banManager implements fail2ban-style auto-banning: after N auth failures
// within a window, an IP is blocked for a duration. Config is read live from
// a getter so settings changes apply without restart.
type banManager struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	banned   map[string]time.Time // ip -> unban time
	config   func() banConfig
	notify   func(string)
}

type banConfig struct {
	enabled   bool
	threshold int
	window    time.Duration
	banFor    time.Duration
}

func newBanManager(config func() banConfig, notify func(string)) *banManager {
	b := &banManager{
		failures: map[string][]time.Time{},
		banned:   map[string]time.Time{},
		config:   config,
		notify:   notify,
	}
	go b.gc()
	return b
}

func (b *banManager) gc() {
	for {
		time.Sleep(5 * time.Minute)
		now := time.Now()
		b.mu.Lock()
		for ip, until := range b.banned {
			if now.After(until) {
				delete(b.banned, ip)
			}
		}
		for ip, times := range b.failures {
			if len(times) == 0 || now.Sub(times[len(times)-1]) > time.Hour {
				delete(b.failures, ip)
			}
		}
		b.mu.Unlock()
	}
}

func clientIP(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// blocked reports whether an IP is currently banned.
func (b *banManager) blocked(remoteAddr string) bool {
	cfg := b.config()
	if !cfg.enabled {
		return false
	}
	ip := clientIP(remoteAddr)
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.banned[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(b.banned, ip)
		return false
	}
	return true
}

// recordFailure notes one auth failure and bans the IP once the threshold is
// reached within the window.
func (b *banManager) recordFailure(remoteAddr string) {
	cfg := b.config()
	if !cfg.enabled {
		return
	}
	ip := clientIP(remoteAddr)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := now.Add(-cfg.window)
	kept := b.failures[ip][:0]
	for _, t := range b.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	b.failures[ip] = kept
	if len(kept) >= cfg.threshold {
		b.banned[ip] = now.Add(cfg.banFor)
		delete(b.failures, ip)
		log.Printf("ban: %s banned for %s (%d failures)", ip, cfg.banFor, cfg.threshold)
		if b.notify != nil {
			b.notify("quicgate: banned " + ip + " after " + itoa(cfg.threshold) + " auth failures")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// wrap rejects banned IPs before any routing happens.
func (b *banManager) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if b.blocked(r.RemoteAddr) {
			http.Error(w, "temporarily banned", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
