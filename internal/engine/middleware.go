package engine

import (
	"crypto/tls"
	"io"
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

// forwardAuth delegates authorization to an external endpoint before the
// request reaches the upstream (Authelia/Authentik/Keycloak-style).
func forwardAuth(fa *store.ForwardAuth, next http.Handler) http.Handler {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: fa.SkipTLSVerify},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		areq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fa.URL, nil)
		if err != nil {
			http.Error(w, "auth misconfigured", http.StatusInternalServerError)
			return
		}
		// Give the auth server the original request context.
		copyForwardAuthHeaders(areq, r)
		resp, err := client.Do(areq)
		if err != nil {
			http.Error(w, "auth backend unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Authorized: copy selected headers (e.g. Remote-User) upstream.
			for _, h := range fa.ResponseHeaders {
				if v := resp.Header.Get(h); v != "" {
					r.Header.Set(h, v)
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		// Not authorized: relay the auth response (often a login redirect).
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
}

func copyForwardAuthHeaders(areq, r *http.Request) {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	areq.Header.Set("X-Forwarded-Method", r.Method)
	areq.Header.Set("X-Forwarded-Proto", scheme)
	areq.Header.Set("X-Forwarded-Host", r.Host)
	areq.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	areq.Header.Set("X-Forwarded-For", clientIP(r.RemoteAddr))
	if c := r.Header.Get("Cookie"); c != "" {
		areq.Header.Set("Cookie", c)
	}
	if a := r.Header.Get("Authorization"); a != "" {
		areq.Header.Set("Authorization", a)
	}
}

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
