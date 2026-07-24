package engine

import (
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
