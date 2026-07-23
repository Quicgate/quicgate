package engine

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzhttp"
	"golang.org/x/time/rate"

	"quicgate/internal/store"
)

// gzipWrap compresses responses when the client sent Accept-Encoding: gzip
// and the content type is compressible. Streaming (flush) is preserved.
func gzipWrap(next http.Handler) http.Handler {
	return gzhttp.GzipHandler(next)
}

// ---- per-client rate limiting ----

type rateLimiter struct {
	mu      sync.Mutex
	rps     rate.Limit
	burst   int
	clients map[string]*rateClient
}

type rateClient struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newRateLimiter(rl *store.RateLimit) *rateLimiter {
	return &rateLimiter{rps: rate.Limit(rl.RPS), burst: rl.Burst, clients: map[string]*rateClient{}}
}

func (r *rateLimiter) allow(remoteAddr string) bool {
	ip := remoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[ip]
	if !ok {
		// Opportunistic GC: prune stale buckets when the map grows.
		if len(r.clients) > 4096 {
			cutoff := time.Now().Add(-10 * time.Minute)
			for k, v := range r.clients {
				if v.lastSeen.Before(cutoff) {
					delete(r.clients, k)
				}
			}
		}
		c = &rateClient{lim: rate.NewLimiter(r.rps, r.burst)}
		r.clients[ip] = c
	}
	c.lastSeen = time.Now()
	return c.lim.Allow()
}

func (r *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.allow(req.RemoteAddr) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// ---- block common exploits ----
// A typed port of the intent behind NPM's block-exploits snippet: obvious
// SQLi, traversal, file-injection and code-injection probes. Deliberately
// coarse; it is a tripwire, not a WAF.

var exploitPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)union[\s+]+select`),
	regexp.MustCompile(`(?i)concat[\s]*\(`),
	regexp.MustCompile(`(?i)(?:;|%3b)[\s]*(?:drop|truncate)[\s]+(?:table|database)`),
	regexp.MustCompile(`\.\./\.\./`),
	regexp.MustCompile(`(?i)(?:/etc/passwd|/etc/shadow|boot\.ini|win\.ini)`),
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)(?:base64_encode|base64_decode|gzinflate|eval)[\s]*\(`),
	regexp.MustCompile(`(?i)(?:_REQUEST|_GET|_POST)[=\[]`),
	regexp.MustCompile(`(?i)proc/self/environ`),
	regexp.MustCompile(`\x00`),
}

func exploitBlocked(r *http.Request) bool {
	probe := r.URL.Path
	if r.URL.RawQuery != "" {
		probe += "?" + r.URL.RawQuery
	}
	if decoded, err := unescapeLoose(probe); err == nil {
		probe = decoded
	}
	for _, re := range exploitPatterns {
		if re.MatchString(probe) {
			return true
		}
	}
	return false
}

// unescapeLoose lowers %-encoding once without failing on stray %.
func unescapeLoose(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, lo := unhex(s[i+1]), unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func blockExploits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exploitBlocked(r) {
			http.Error(w, "request blocked", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- redirect + dead hosts ----

func buildRedirectHandler(rd store.Redirect) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := rd.TargetScheme
		if scheme == "auto" {
			if r.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		loc := scheme + "://" + rd.TargetHost
		if rd.PreservePath {
			loc += r.URL.RequestURI()
		}
		http.Redirect(w, r, loc, rd.HTTPCode)
	})
}

func deadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDefault404(w)
	})
}
