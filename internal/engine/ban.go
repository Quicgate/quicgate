package engine

import (
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// banManager implements fail2ban-style auto-banning: after N auth failures
// within a window, an IP is blocked for a duration. Config comes from a getter
// that returns the configuration the last reload compiled, so settings changes
// apply without a restart and no request reads the database.
// banMaxTracked caps the addresses the ban manager tracks, per map. At the cap
// an arbitrary entry is dropped. A variable so tests can use a small cap.
var banMaxTracked = 65536

type banManager struct {
	mu       sync.Mutex
	failures map[string]*failureTrail
	banned   map[string]banEntry // by client address
	config   func() banConfig
	notify   func(string)
	refused  atomic.Uint64 // requests turned away because their client is banned
}

// failureTrail is an address's recent refusals, and the last one's details.
type failureTrail struct {
	times  []time.Time
	host   string
	reason string
}

// banEntry is one banned address: when and why it was banned.
type banEntry struct {
	since, until time.Time
	failures     int
	host         string // the host the last refused request asked for
	reason       string // why that request was refused
}

// BanInfo describes a banned address for the admin API.
type BanInfo struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country,omitempty"` // with a GeoIP database: ISO code, "LAN" or "unknown"
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"` // refusals within the window that led to the ban
	Host     string    `json:"host"`
	Reason   string    `json:"reason"`
}

type banConfig struct {
	enabled   bool
	threshold int
	window    time.Duration
	banFor    time.Duration
}

func newBanManager(config func() banConfig, notify func(string)) *banManager {
	b := &banManager{
		failures: map[string]*failureTrail{},
		banned:   map[string]banEntry{},
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
		for ip, ban := range b.banned {
			if now.After(ban.until) {
				delete(b.banned, ip)
			}
		}
		for ip, trail := range b.failures {
			if len(trail.times) == 0 || now.Sub(trail.times[len(trail.times)-1]) > time.Hour {
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
	ban, ok := b.banned[ip]
	if !ok {
		return false
	}
	if time.Now().After(ban.until) {
		delete(b.banned, ip)
		return false
	}
	return true
}

// recordFailure notes one refused request for host, and why it was refused,
// and bans the address once the threshold is reached within the window.
func (b *banManager) recordFailure(remoteAddr, host, reason string) {
	cfg := b.config()
	if !cfg.enabled {
		return
	}
	ip := clientIP(remoteAddr)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := now.Add(-cfg.window)
	trail := b.failures[ip]
	if trail == nil {
		evictOne(b.failures, banMaxTracked)
		trail = &failureTrail{}
		b.failures[ip] = trail
	}
	kept := trail.times[:0]
	for _, t := range trail.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	trail.times = append(kept, now)
	// The host comes from the request, so it is capped like any client input.
	trail.host, trail.reason = truncate(host, 253), reason
	if len(trail.times) >= cfg.threshold {
		if _, known := b.banned[ip]; !known {
			evictOne(b.banned, banMaxTracked)
		}
		b.banned[ip] = banEntry{since: now, until: now.Add(cfg.banFor), failures: len(trail.times), host: trail.host, reason: trail.reason}
		delete(b.failures, ip)
		log.Printf("ban: %s banned for %s (%d failures)", ip, cfg.banFor, cfg.threshold)
		if b.notify != nil {
			// The webhook can be slow or unreachable, and every request takes
			// b.mu: never wait for it here.
			go b.notify("quicgate: banned " + ip + " after " + itoa(cfg.threshold) + " auth failures")
		}
	}
}

// evictOne drops arbitrary entries until m is below max.
func evictOne[V any](m map[string]V, max int) {
	for k := range m {
		if len(m) < max {
			return
		}
		delete(m, k)
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

// bannedCount reports how many addresses are banned right now.
func (b *banManager) bannedCount() int {
	if !b.config().enabled {
		return 0
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, ban := range b.banned {
		if now.Before(ban.until) {
			n++
		}
	}
	return n
}

// list returns the addresses banned now, most recent first. country names an
// address's country, or is nil to leave it out.
func (b *banManager) list(country func(ip string) string) []BanInfo {
	out := []BanInfo{}
	if !b.config().enabled {
		return out
	}
	now := time.Now()
	b.mu.Lock()
	for ip, ban := range b.banned {
		if now.Before(ban.until) {
			out = append(out, BanInfo{IP: ip, Since: ban.since, Until: ban.until, Failures: ban.failures, Host: ban.host, Reason: ban.reason})
		}
	}
	b.mu.Unlock()
	if country != nil {
		for i := range out {
			out[i].Country = country(out[i].IP)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.After(out[j].Since)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// unban lifts a ban and forgets the address's recent refusals. It reports
// whether the address was banned.
func (b *banManager) unban(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.banned[ip]
	delete(b.banned, ip)
	delete(b.failures, ip)
	return ok
}

// Bans lists the addresses banned now, most recent first, with their country
// when a GeoIP database is loaded.
func (e *Engine) Bans() []BanInfo {
	var country func(string) string
	if e.geo.loaded() {
		country = func(ip string) string { return clientCountry(ip, e.geo.country) }
	}
	return e.ban.list(country)
}

// Unban lifts the ban on an address. It reports whether the address was
// banned.
func (e *Engine) Unban(ip string) bool { return e.ban.unban(ip) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// wrap rejects banned IPs before any routing happens.
func (b *banManager) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if b.blocked(r.RemoteAddr) {
			b.refused.Add(1)
			http.Error(w, "temporarily banned", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
