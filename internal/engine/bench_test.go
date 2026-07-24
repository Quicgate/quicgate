package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"quicgate/internal/store"
)

// benchEngine builds an engine with one proxy host in front of a trivial local
// backend. Options let a benchmark exercise middleware (access lists, cache).
func benchEngine(b *testing.B, opts store.Options, acl *store.AccessList) *Engine {
	b.Helper()
	dir := b.TempDir()
	st, err := store.Open(dir + "/quicgate.db")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	e := New(Config{DisableTLS: true, DataDir: dir}, st)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello from the backend")
	}))
	b.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(u.Port())

	h := &store.Host{
		Type: "proxy", Domains: []string{"bench.test"}, CertMode: "none", Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: u.Hostname(), Port: port}, Options: opts,
	}
	if acl != nil {
		if err := st.CreateAccessList(acl); err != nil {
			b.Fatal(err)
		}
		h.AccessListID = &acl.ID
	}
	if err := st.CreateHost(h); err != nil {
		b.Fatal(err)
	}
	if err := e.Reload(context.Background()); err != nil {
		b.Fatal(err)
	}
	return e
}

// BenchmarkRouteLookup measures the routing-table lookup in isolation, the hot
// path every request pays. Shows routing is never the bottleneck.
func BenchmarkRouteLookup(b *testing.B) {
	e := benchEngine(b, store.Options{}, nil)
	tbl := e.table.Load()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if tbl.lookup("bench.test") == nil {
				b.Fatal("no route")
			}
		}
	})
}

// serveOnce drives one request through the full pipeline via a recorder (no
// socket), measuring the proxy logic overhead.
func serveOnce(b *testing.B, e *Engine) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest(http.MethodGet, "http://bench.test/", nil)
			r.Host = "bench.test"
			r.RemoteAddr = "10.0.0.5:40000"
			rr := httptest.NewRecorder()
			e.serveHTTPS(rr, r)
			if rr.Code != http.StatusOK {
				b.Fatalf("status %d", rr.Code)
			}
		}
	})
}

// BenchmarkServeProxy: full routing -> middleware -> reverse proxy to a local
// backend, in-process.
func BenchmarkServeProxy(b *testing.B) { serveOnce(b, benchEngine(b, store.Options{}, nil)) }

// BenchmarkServeProxyAccessList: same, with an IP access list evaluated per
// request (measures access-list overhead).
func BenchmarkServeProxyAccessList(b *testing.B) {
	acl := &store.AccessList{Name: "lan", Satisfy: "any", Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	serveOnce(b, benchEngine(b, store.Options{}, acl))
}

// loadTest drives real HTTP over a loopback socket through the full engine: the
// closest reproducible requests/sec figure. Client, engine and backend all run
// on this machine, so it reflects a full round-trip, not server-only capacity.
func loadTest(b *testing.B, e *Engine) {
	front := httptest.NewServer(http.HandlerFunc(e.serveHTTPS))
	b.Cleanup(front.Close)
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 512}}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
			req.Host = "bench.test"
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// BenchmarkProxyThroughput: end-to-end req/s over a real socket, proxying to a
// local backend.
func BenchmarkProxyThroughput(b *testing.B) { loadTest(b, benchEngine(b, store.Options{}, nil)) }

// BenchmarkCacheHitThroughput: same, but the host caches responses, so hits are
// served from memory without touching the backend.
func BenchmarkCacheHitThroughput(b *testing.B) {
	e := benchEngine(b, store.Options{CacheSec: 300}, nil)
	// Prime the cache once (keyed by method+host+path) so the loop measures hits.
	pr := httptest.NewRequest(http.MethodGet, "http://bench.test/", nil)
	pr.Host = "bench.test"
	e.serveHTTPS(httptest.NewRecorder(), pr)
	loadTest(b, e)
}
