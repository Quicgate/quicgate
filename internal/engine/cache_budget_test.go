package engine

import (
	"bytes"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// The cache is bounded in bytes, not only in entries: cache-busting query
// strings cannot grow it past the budget, and the least recently used
// response goes first. Before, 512 entries of up to 2 MiB each were kept per
// host, a gibibyte in memory.
func TestCacheStaysWithinItsByteBudget(t *testing.T) {
	c := newRespCache(time.Minute, 0)
	c.maxBytes = 64 << 10
	entry := func() *cacheEntry {
		return &cacheEntry{status: http.StatusOK, header: http.Header{"Content-Type": {"text/plain"}},
			body: bytes.Repeat([]byte("x"), 1<<10), expires: time.Now().Add(time.Minute)}
	}
	key := func(i int) string { return fmt.Sprintf("GET h.test /asset?v=%d ae=", i) }
	stored := func(i int) bool { // without counting as a use
		c.mu.Lock()
		defer c.mu.Unlock()
		_, ok := c.m[key(i)]
		return ok
	}

	c.put(key(0), entry())
	per := c.bytes
	if per <= 1<<10 || per > 2<<10 {
		t.Fatalf("one entry with a 1 KiB body counts %d bytes, want the body plus a modest overhead", per)
	}
	fit := c.maxBytes / per // about this many entries fit
	for i := 1; i < fit+10; i++ {
		c.put(key(i), entry())
		if c.bytes > c.maxBytes {
			t.Fatalf("after %d entries the cache holds %d bytes, over its budget of %d", i+1, c.bytes, c.maxBytes)
		}
	}
	if len(c.m) > fit {
		t.Fatalf("%d entries stored, at most %d fit the budget", len(c.m), fit)
	}
	for _, i := range []int{0, 9} {
		if stored(i) {
			t.Fatalf("entry %d, among the ten oldest, survived %d newer ones", i, fit)
		}
	}
	if !stored(fit + 9) {
		t.Fatal("the newest entry is missing")
	}

	// Least recently used, not oldest: the oldest entry still stored is read,
	// and then outlives the untouched entries stored just after it.
	oldest := -1
	for i := 0; i < fit+10 && oldest < 0; i++ {
		if stored(i) {
			oldest = i
		}
	}
	if c.get(key(oldest)) == nil {
		t.Fatalf("entry %d is stored but cannot be read", oldest)
	}
	for i := fit + 10; i < fit+13; i++ {
		c.put(key(i), entry())
	}
	if !stored(oldest) {
		t.Fatalf("entry %d was read a moment ago and was evicted before entries not read since they were stored", oldest)
	}
	for i := oldest + 1; i <= oldest+3; i++ {
		if stored(i) {
			t.Fatalf("entry %d, not read since it was stored, outlived three newer entries while an older, read one went", i)
		}
	}

	// Storing under a key again does not count the entry twice, and an entry
	// the whole budget cannot hold is not stored.
	before := c.bytes
	c.put(key(fit+12), entry())
	if c.bytes != before {
		t.Fatalf("storing an entry again changed the byte count from %d to %d", before, c.bytes)
	}
	huge := entry()
	huge.body = bytes.Repeat([]byte("x"), c.maxBytes)
	c.put("huge", huge)
	if c.get("huge") != nil || c.bytes > c.maxBytes {
		t.Fatalf("an entry over the whole budget was stored (%d bytes held)", c.bytes)
	}
}

// Through the proxy: a client varying the query string does not grow a host's
// cache past its budget. The first response is evicted and fetched again, the
// last is still served from the cache.
func TestCacheBudgetEndToEnd(t *testing.T) {
	old := cacheMaxBytesPerHost
	cacheMaxBytesPerHost = 16 << 10
	t.Cleanup(func() { cacheMaxBytesPerHost = old })
	e, st := newTestEngine(t)
	var renders atomic.Int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		renders.Add(1)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<10))
	})
	cachedHost(t, st, "budget.test", up, nil)
	reload(t, e)

	for i := 0; i < 40; i++ {
		if rr := req(e, "GET", "budget.test", fmt.Sprintf("/asset?v=%d", i), "203.0.113.9", nil); rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "MISS" {
			t.Fatalf("asset %d: %d X-Cache %q, want a 200 MISS", i, rr.Code, rr.Header().Get("X-Cache"))
		}
	}
	if rr := req(e, "GET", "budget.test", "/asset?v=39", "203.0.113.10", nil); rr.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("the newest asset: X-Cache %q, want HIT", rr.Header().Get("X-Cache"))
	}
	if rr := req(e, "GET", "budget.test", "/asset?v=0", "203.0.113.10", nil); rr.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("the oldest asset: X-Cache %q, want MISS (evicted to stay within the budget)", rr.Header().Get("X-Cache"))
	}
	if n := renders.Load(); n != 41 {
		t.Fatalf("%d renders, want 41: forty distinct assets and the evicted one again", n)
	}
}
