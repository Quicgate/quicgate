package engine

import (
	"bytes"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// respCache is a small bounded in-memory response cache for one host. It caches
// 200 responses to GET/HEAD when they are safely cacheable, and serves them
// until they expire. A fresh cache is built on every reload, so a config change
// clears it.
//
// The cache is shared by every client of the host, so it only ever holds
// anonymous responses: a request tied to an identity (credentials, a cookie, a
// gate that admitted it by identity) is neither answered from it nor stored.
type respCache struct {
	mu  sync.Mutex
	m   map[string]*cacheEntry
	ttl time.Duration
	max int
}

type cacheEntry struct {
	status  int
	header  http.Header
	body    []byte
	expires time.Time
}

const cacheMaxBodyBytes = 2 << 20 // 2 MiB: do not cache large bodies

func newRespCache(ttl time.Duration, max int) *respCache {
	if max <= 0 {
		max = 512
	}
	return &respCache{m: map[string]*cacheEntry{}, ttl: ttl, max: max}
}

func (c *respCache) get(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(c.m, key)
		return nil
	}
	return e
}

func (c *respCache) put(key string, e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		now := time.Now()
		for k, v := range c.m { // drop expired entries first
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max { // still full: drop an arbitrary entry
			for k := range c.m {
				delete(c.m, k)
				break
			}
		}
	}
	c.m[key] = e
}

// sharedCacheable reports whether r may be answered from, or stored in, the
// shared cache. A request tied to an identity is not: credentials that arrived
// with it (even if an access list has stripped them since), any cookie (quicgate
// cannot tell which of an application's cookies carry a session), or a gate
// that admitted it by identity.
func sharedCacheable(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return false
	}
	// A client certificate identifies the client as surely as a cookie does, and
	// the upstream may render per certificate.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return false
	}
	if ra := requestAuthOf(r); ra != nil && (ra.hadAuthorization || ra.identified) {
		return false
	}
	return true
}

// cacheKey varies on the normalised Accept-Encoding as well as the URL, so a
// compressed upstream body is only ever replayed to a client that accepts that
// encoding.
func cacheKey(r *http.Request) string {
	return r.Method + " " + strings.ToLower(r.Host) + " " + r.URL.RequestURI() + " ae=" + normalizeAcceptEncoding(r.Header.Get("Accept-Encoding"))
}

// normalizeAcceptEncoding reduces an Accept-Encoding value to its sorted set of
// acceptable codings, so equivalent headers share one cache entry.
func normalizeAcceptEncoding(v string) string {
	var codings []string
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		coding, params, _ := strings.Cut(part, ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding == "" || seen[coding] {
			continue
		}
		if q, ok := strings.CutPrefix(strings.ReplaceAll(strings.ToLower(params), " ", ""), "q="); ok {
			if f, err := strconv.ParseFloat(q, 64); err == nil && f == 0 {
				continue // explicitly refused
			}
		}
		seen[coding] = true
		codings = append(codings, coding)
	}
	sort.Strings(codings)
	return strings.Join(codings, ",")
}

// wrap serves cache HITs and records cacheable MISSes.
func (c *respCache) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sharedCacheable(r) {
			next.ServeHTTP(w, r)
			return
		}
		reqCC := cacheControl(r.Header)
		noStore := hasCacheDirective(reqCC, "no-store")
		key := cacheKey(r)
		// A request asking for a fresh or unstored response skips the lookup.
		if !noStore && !hasCacheDirective(reqCC, "no-cache") {
			if e := c.get(key); e != nil {
				h := w.Header()
				for k, v := range e.header {
					h[k] = v
				}
				h.Set("X-Cache", "HIT")
				w.WriteHeader(e.status)
				if r.Method == http.MethodGet {
					_, _ = w.Write(e.body)
				}
				return
			}
		}
		rec := &cacheRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if noStore || !rec.cacheable || rec.buf == nil {
			return
		}
		ttl := c.ttl
		if age, ok := freshnessLifetime(cacheControl(rec.savedHeader)); ok {
			if age <= 0 {
				return // already stale by the origin's own account (max-age=0)
			}
			if age < ttl {
				ttl = age
			}
		}
		if ttl > 0 {
			c.put(key, &cacheEntry{status: rec.status, header: rec.savedHeader, body: rec.buf.Bytes(), expires: time.Now().Add(ttl)})
		}
	})
}

// cacheRecorder tees a cacheable response into a buffer while writing through
// to the client.
type cacheRecorder struct {
	http.ResponseWriter
	status      int
	buf         *bytes.Buffer
	savedHeader http.Header
	cacheable   bool
	wrote       bool
}

func (r *cacheRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = code
	r.decide()
	r.ResponseWriter.Header().Set("X-Cache", "MISS")
	r.ResponseWriter.WriteHeader(code)
}

func (r *cacheRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	if r.cacheable && r.buf != nil {
		if r.buf.Len()+len(b) > cacheMaxBodyBytes {
			r.cacheable, r.buf = false, nil
		} else {
			r.buf.Write(b)
		}
	}
	return r.ResponseWriter.Write(b)
}

func (r *cacheRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *cacheRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// decide inspects the response headers at WriteHeader time and snapshots them
// when the response is safe to cache.
func (r *cacheRecorder) decide() {
	if r.status != http.StatusOK {
		return
	}
	h := r.ResponseWriter.Header()
	cc := cacheControl(h)
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return
	}
	if h.Get("Set-Cookie") != "" {
		return
	}
	// The key varies on Accept-Encoding only, so any other Vary (or "*") would
	// need a key this cache does not build: do not store those.
	for _, v := range h.Values("Vary") {
		for _, field := range strings.Split(v, ",") {
			if f := strings.TrimSpace(field); f != "" && !strings.EqualFold(f, "accept-encoding") {
				return
			}
		}
	}
	r.savedHeader = h.Clone()
	r.cacheable = true
	r.buf = &bytes.Buffer{}
}

// cacheControl returns every Cache-Control field of h as one lower-cased list.
// The header may be split across several fields, and a directive in any of
// them applies.
func cacheControl(h http.Header) string {
	return strings.ToLower(strings.Join(h.Values("Cache-Control"), ","))
}

// hasCacheDirective reports whether a lower-cased Cache-Control value carries
// the named directive (with or without an argument).
func hasCacheDirective(cc, name string) bool {
	for _, part := range strings.Split(cc, ",") {
		d, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if d == name {
			return true
		}
	}
	return false
}

// freshnessLifetime returns how long the origin allows a shared cache to keep a
// response: s-maxage when present, else max-age. ok is false when neither is
// given, so the host's own cache TTL applies.
func freshnessLifetime(cc string) (time.Duration, bool) {
	maxAge, sMaxAge := -1, -1
	for _, part := range strings.Split(strings.ToLower(cc), ",") {
		name, val, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(val, `"`))
		if err != nil {
			continue
		}
		switch name {
		case "max-age":
			maxAge = n
		case "s-maxage":
			sMaxAge = n
		}
	}
	switch {
	case sMaxAge >= 0:
		return time.Duration(sMaxAge) * time.Second, true
	case maxAge >= 0:
		return time.Duration(maxAge) * time.Second, true
	}
	return 0, false
}
