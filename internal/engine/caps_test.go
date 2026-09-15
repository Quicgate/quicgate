package engine

import (
	"fmt"
	"testing"
	"time"

	"quicgate/internal/store"
)

// Q14: per-client state that attacker-chosen source addresses can create is
// capped.

func TestRateLimiterClientCap(t *testing.T) {
	old := rateLimitMaxClients
	rateLimitMaxClients = 3
	t.Cleanup(func() { rateLimitMaxClients = old })

	rl := newRateLimiter(&store.RateLimit{RPS: 1, Burst: 1})
	for i := 0; i < 10; i++ {
		rl.allow(fmt.Sprintf("198.51.100.%d:1", i))
	}
	if n := len(rl.clients); n > 3 {
		t.Fatalf("rate limiter tracks %d clients, cap is 3", n)
	}
}

func TestBanManagerTrackingCap(t *testing.T) {
	old := banMaxTracked
	banMaxTracked = 3
	t.Cleanup(func() { banMaxTracked = old })

	b := &banManager{
		failures: map[string]*failureTrail{},
		banned:   map[string]banEntry{},
		config: func() banConfig {
			return banConfig{enabled: true, threshold: 2, window: time.Hour, banFor: time.Hour}
		},
	}
	for i := 0; i < 10; i++ {
		b.recordFailure(fmt.Sprintf("198.51.100.%d:1", i), "test.host", "test") // one failure each: tracked, not banned
	}
	if n := len(b.failures); n > 3 {
		t.Fatalf("ban manager tracks failures for %d addresses, cap is 3", n)
	}
	for i := 0; i < 10; i++ {
		addr := fmt.Sprintf("203.0.113.%d:1", i)
		b.recordFailure(addr, "test.host", "test")
		b.recordFailure(addr, "test.host", "test") // second failure: banned
	}
	if n := len(b.banned); n > 3 {
		t.Fatalf("ban manager holds %d bans, cap is 3", n)
	}
}
