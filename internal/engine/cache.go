package engine

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// respCache is a small bounded in-memory response cache for one host. It caches
// 200 responses to GET/HEAD when they are safely cacheable, and serves them
// until they expire. A fresh cache is built on every reload, so a config change
// clears it.
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

// wrap serves cache HITs and records cacheable MISSes.
func (c *respCache) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only safe, unauthenticated reads are cacheable.
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Method + " " + r.Host + " " + r.URL.RequestURI()
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
		rec := &cacheRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.cacheable && rec.buf != nil {
			ttl := c.ttl
			if ma := maxAge(rec.savedHeader.Get("Cache-Control")); ma > 0 && time.Duration(ma)*time.Second < ttl {
				ttl = time.Duration(ma) * time.Second
			}
			if ttl > 0 {
				c.put(key, &cacheEntry{status: rec.status, header: rec.savedHeader, body: rec.buf.Bytes(), expires: time.Now().Add(ttl)})
			}
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
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return
	}
	if h.Get("Set-Cookie") != "" {
		return
	}
	if vary := strings.TrimSpace(h.Get("Vary")); vary != "" && !strings.EqualFold(vary, "accept-encoding") {
		return
	}
	r.savedHeader = h.Clone()
	r.cacheable = true
	r.buf = &bytes.Buffer{}
}

// maxAge parses the max-age directive (seconds) from a Cache-Control value.
func maxAge(cc string) int {
	for _, part := range strings.Split(strings.ToLower(cc), ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 0
}
