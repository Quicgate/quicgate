package engine

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"quicgate/internal/store"
)

// TestUpstreamTransportPooling locks in the keep-alive pool sizing that keeps a
// high-throughput host reusing backend connections instead of churning them
// (dial + TLS per burst -> Windows ephemeral-port exhaustion -> 502s).
func TestUpstreamTransportPooling(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		tr := newUpstreamTransport(store.Host{Upstream: store.Upstream{Scheme: "http"}})
		if tr.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHost {
			t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
		}
		// Single backend: the global cap must not sit below the per-host budget,
		// or Go's default of 100 would silently throttle it.
		if tr.MaxIdleConns != defaultMaxIdleConnsPerHost {
			t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, defaultMaxIdleConnsPerHost)
		}
		if tr.IdleConnTimeout != 90*time.Second {
			t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
		}
		if !tr.ForceAttemptHTTP2 {
			t.Error("ForceAttemptHTTP2 = false, want true")
		}
	})

	t.Run("per-host override", func(t *testing.T) {
		tr := newUpstreamTransport(store.Host{
			Upstream: store.Upstream{Scheme: "http"},
			Options:  store.Options{MaxIdleConnsPerHost: 64},
		})
		if tr.MaxIdleConnsPerHost != 64 {
			t.Errorf("MaxIdleConnsPerHost = %d, want 64", tr.MaxIdleConnsPerHost)
		}
		if tr.MaxIdleConns != 64 {
			t.Errorf("MaxIdleConns = %d, want 64", tr.MaxIdleConns)
		}
	})

	t.Run("global cap scales with backend set", func(t *testing.T) {
		// primary + 2 pool members + 1 location = 4 distinct backends, all sharing
		// this transport, so each may hold a full per-host pool.
		tr := newUpstreamTransport(store.Host{
			Upstream:  store.Upstream{Scheme: "http"},
			Upstreams: make([]store.Upstream, 2),
			Locations: make([]store.Location, 1),
		})
		if tr.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHost {
			t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
		}
		if want := defaultMaxIdleConnsPerHost * 4; tr.MaxIdleConns != want {
			t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, want)
		}
	})

	t.Run("idle timeout override", func(t *testing.T) {
		tr := newUpstreamTransport(store.Host{
			Upstream: store.Upstream{Scheme: "http"},
			Options:  store.Options{IdleTimeoutSec: 30},
		})
		if tr.IdleConnTimeout != 30*time.Second {
			t.Errorf("IdleConnTimeout = %v, want 30s", tr.IdleConnTimeout)
		}
	})

	t.Run("https carries tls config", func(t *testing.T) {
		tr := newUpstreamTransport(store.Host{
			Upstream: store.Upstream{Scheme: "https"},
			Options:  store.Options{SkipTLSVerify: true, UpstreamSNI: "backend.internal"},
		})
		if tr.TLSClientConfig == nil {
			t.Fatal("TLSClientConfig = nil, want set for https upstream")
		}
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify = false, want true")
		}
		if tr.TLSClientConfig.ServerName != "backend.internal" {
			t.Errorf("ServerName = %q, want backend.internal", tr.TLSClientConfig.ServerName)
		}
	})
}

// TestUpstreamConnectionReuse proves the pooling fix does what it claims: under
// concurrent load to one HTTP/1.1 backend, a small idle pool dials a fresh
// connection per burst (the churn that exhausts Windows ephemeral ports),
// whereas the engine default reuses a bounded set. It measures churn directly
// by counting how many distinct TCP connections the backend accepts.
func TestUpstreamConnectionReuse(t *testing.T) {
	const (
		workers   = 24 // concurrent in-flight requests -> peak simultaneous backend conns
		perWorker = 40
	)

	// run drives the workload against a host configured with maxIdlePerHost and
	// returns how many new backend connections were opened. Fewer == better reuse.
	run := func(maxIdlePerHost int) int64 {
		var newConns int64
		be := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A tiny delay keeps requests overlapping, so concurrency genuinely
			// forces `workers` simultaneous connections rather than one reused serially.
			time.Sleep(time.Millisecond)
			_, _ = io.WriteString(w, "ok")
		}))
		be.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				atomic.AddInt64(&newConns, 1)
			}
		}
		be.Start()
		defer be.Close()

		e, st := newTestEngine(t)
		u, _ := url.Parse(be.URL)
		port, _ := strconv.Atoi(u.Port())
		h := &store.Host{
			Type: "proxy", Domains: []string{"reuse.test"}, CertMode: "none", Enabled: true,
			Upstream: store.Upstream{Scheme: "http", Host: u.Hostname(), Port: port},
			Options:  store.Options{MaxIdleConnsPerHost: maxIdlePerHost},
		}
		if err := st.CreateHost(h); err != nil {
			t.Fatal(err)
		}
		reload(t, e)

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < perWorker; j++ {
					r := httptest.NewRequest(http.MethodGet, "http://reuse.test/", nil)
					r.Host = "reuse.test"
					r.RemoteAddr = "10.0.0.5:40000"
					rr := httptest.NewRecorder()
					e.serveHTTPS(rr, r) // recorder front: the only real sockets are backend-side
					if rr.Code != http.StatusOK {
						t.Errorf("status %d", rr.Code)
						return
					}
				}
			}()
		}
		wg.Wait()
		return atomic.LoadInt64(&newConns)
	}

	small := run(2)   // starved pool: must re-dial once concurrency exceeds the 2 idle slots
	large := run(256) // engine default: retains and reuses the whole working set
	total := int64(workers * perWorker)
	t.Logf("backend connections opened over %d requests: smallPool(2)=%d  largePool(256)=%d", total, small, large)

	// The whole point: a bigger idle pool opens strictly fewer backend connections.
	if large >= small {
		t.Errorf("expected larger idle pool to open FEWER backend conns; got small(2)=%d, large(256)=%d", small, large)
	}
	// With the default pool no connection is ever evicted (working set < 256, well
	// under IdleConnTimeout), so distinct conns can't exceed peak concurrency by
	// much. A generous 2x bound guards against regressing to per-request dials.
	if bound := int64(workers) * 2; large > bound {
		t.Errorf("large pool opened %d backend conns over %d requests, want <= %d (should reuse, not churn)", large, total, bound)
	}
}
