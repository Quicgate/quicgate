package engine

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"quicgate/internal/store"
)

// fakeDNS is a scripted resolver with a controllable clock.
type fakeDNS struct {
	answers map[string][]net.IP // nil entry = lookup fails
	now     time.Time
}

func (f *fakeDNS) cache() *dnsCache {
	return &dnsCache{
		lookup: func(host string) ([]net.IP, error) {
			if ips := f.answers[host]; ips != nil {
				return ips, nil
			}
			return nil, errors.New("simulated resolver failure")
		},
		now:     func() time.Time { return f.now },
		entries: map[string]dnsEntry{},
	}
}

func ddnsList(host string) store.AccessList {
	return store.AccessList{Name: "home", Satisfy: "any", Rules: []store.AccessRule{{Action: "allow", Host: host}}}
}

// Q04: a failing lookup keeps the last good addresses, within the bound.
func TestDNSLastKnownGoodKeepsRule(t *testing.T) {
	f := &fakeDNS{answers: map[string][]net.IP{"home.example": {net.ParseIP("198.51.100.7")}}, now: time.Unix(1_700_000_000, 0)}
	dns := f.cache()
	if c := compileAccess(ddnsList("home.example"), nil, nil, dns); !c.ipAllowed("198.51.100.7:1", "GET") {
		t.Fatal("resolved address not admitted")
	}

	f.answers["home.example"] = nil // DNS outage
	f.now = f.now.Add(time.Hour)
	c := compileAccess(ddnsList("home.example"), nil, nil, dns)
	if !c.ipAllowed("198.51.100.7:1", "GET") {
		t.Fatal("last-known-good address dropped during a DNS outage")
	}
	if c.ipAllowed("203.0.113.9:1", "GET") {
		t.Fatal("outsider admitted during a DNS outage")
	}
	if len(c.warnings) == 0 || !strings.Contains(strings.Join(c.warnings, " "), "last resolved") {
		t.Fatalf("no operator warning about the stale answer: %v", c.warnings)
	}

	// Past the bound the rule closes instead of trusting a day-old answer.
	f.now = f.now.Add(dnsLastKnownGoodMaxAge + time.Minute)
	c = compileAccess(ddnsList("home.example"), nil, nil, dns)
	if c.ipAllowed("198.51.100.7:1", "GET") || c.ipAllowed("203.0.113.9:1", "GET") {
		t.Fatal("expired last-known-good answer still admitted a client")
	}
}

// Q04: a successful lookup replaces the previous addresses entirely.
func TestDNSRecoveryReplacesAddresses(t *testing.T) {
	f := &fakeDNS{answers: map[string][]net.IP{"home.example": {net.ParseIP("198.51.100.7")}}, now: time.Unix(1_700_000_000, 0)}
	dns := f.cache()
	compileAccess(ddnsList("home.example"), nil, nil, dns)

	f.answers["home.example"] = []net.IP{net.ParseIP("198.51.100.99")}
	c := compileAccess(ddnsList("home.example"), nil, nil, dns)
	if !c.ipAllowed("198.51.100.99:1", "GET") {
		t.Fatal("new address not admitted after the name moved")
	}
	if c.ipAllowed("198.51.100.7:1", "GET") {
		t.Fatal("old address still admitted after the name moved")
	}
}

// Q04: IPv6 answers are single-address rules too, and one failing rule does not
// affect the others.
func TestDNSIPv6AndPartialFailure(t *testing.T) {
	f := &fakeDNS{answers: map[string][]net.IP{"v6.example": {net.ParseIP("2001:db8::7")}}, now: time.Unix(1_700_000_000, 0)}
	list := store.AccessList{Name: "mixed", Satisfy: "any", Rules: []store.AccessRule{
		{Action: "allow", Host: "down.example"},
		{Action: "allow", Host: "v6.example"},
		{Action: "allow", CIDR: "10.0.0.0/8"},
	}}
	c := compileAccess(list, nil, nil, f.cache())
	for addr, want := range map[string]bool{
		net.JoinHostPort("2001:db8::7", "1"): true,
		net.JoinHostPort("2001:db8::8", "1"): false,
		"10.1.2.3:1":                         true,
		"203.0.113.9:1":                      false,
	} {
		if got := c.ipAllowed(addr, "GET"); got != want {
			t.Fatalf("ipAllowed(%s) = %v, want %v", addr, got, want)
		}
	}
}

// Q03: forward auth can admit a request that carries neither a cookie nor an
// Authorization header, here by identifying the user from the client address
// (a VPN or IP-to-user mapping). The identity is still personal, so the
// response must not be shared.
func TestCacheBypassesForwardAuthIdentity(t *testing.T) {
	e, st := newTestEngine(t)
	users := map[string]string{"203.0.113.9": "alice", "203.0.113.10": "bob"}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := users[r.Header.Get("X-Forwarded-For")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Remote-User", u)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(auth.Close)
	var hits int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "render-%d for %s", atomic.AddInt32(&hits, 1), r.Header.Get("Remote-User"))
	})
	cachedHost(t, st, "fa-cache.test", up, func(h *store.Host) {
		h.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL, ResponseHeaders: []string{"Remote-User"}}
	})
	reload(t, e)

	a := req(e, "GET", "fa-cache.test", "/me", "203.0.113.9", nil)
	b := req(e, "GET", "fa-cache.test", "/me", "203.0.113.10", nil)
	if a.Code != http.StatusOK || b.Code != http.StatusOK {
		t.Fatalf("forward auth: alice=%d bob=%d, want 200", a.Code, b.Code)
	}
	if b.Header().Get("X-Cache") == "HIT" || !strings.HasSuffix(b.Body.String(), "for bob") {
		t.Fatalf("bob got %q (X-Cache %q), want his own uncached response", b.Body.String(), b.Header().Get("X-Cache"))
	}
}
