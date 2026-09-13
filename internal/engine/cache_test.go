package engine

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"quicgate/internal/store"
)

// The response cache is shared by every client of a host. These tests pin the
// rule that it never hands one identity's response to another.

func cachedHost(t *testing.T, st *store.Store, domain string, up store.Upstream, mutate func(*store.Host)) {
	t.Helper()
	h := &store.Host{Type: "proxy", Domains: []string{domain}, Upstream: up}
	h.Options.CacheSec = 60
	if mutate != nil {
		mutate(h)
	}
	mustCreateHost(t, st, h)
}

// Q03: an application session cookie makes a response personal.
func TestCacheNeverSharesAcrossCookies(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		ck, _ := r.Cookie("app_session")
		v := "anonymous"
		if ck != nil {
			v = ck.Value
		}
		fmt.Fprint(w, "account for "+v)
	})
	cachedHost(t, st, "app.test", up, nil)
	reload(t, e)

	a := req(e, "GET", "app.test", "/account", "203.0.113.9", map[string]string{"Cookie": "app_session=alice"})
	b := req(e, "GET", "app.test", "/account", "203.0.113.10", map[string]string{"Cookie": "app_session=bob"})
	if a.Body.String() != "account for alice" {
		t.Fatalf("alice got %q", a.Body.String())
	}
	if b.Body.String() != "account for bob" || b.Header().Get("X-Cache") == "HIT" {
		t.Fatalf("bob got %q (X-Cache %q), want his own uncached response", b.Body.String(), b.Header().Get("X-Cache"))
	}
}

// Q03: two separately authenticated SSO users must never share a response.
func TestCacheBypassesOIDCSessions(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "account for "+r.Header.Get("Remote-User"))
	})
	cachedHost(t, st, "sso-cache.test", up, func(h *store.Host) {
		h.Options.OIDC = &store.OIDCAuth{ProviderID: pid, PassIdentity: true}
	})
	reload(t, e)

	idp.email = "alice@example.com"
	alice := oidcLoginAt(t, e, idp, "sso-cache.test", "/me")
	idp.email = "bob@example.com"
	bob := oidcLoginAt(t, e, idp, "sso-cache.test", "/me")

	if rr := req(e, "GET", "sso-cache.test", "/me", "203.0.113.9", map[string]string{"Cookie": alice}); rr.Body.String() != "account for alice@example.com" {
		t.Fatalf("alice got %q", rr.Body.String())
	}
	rr := req(e, "GET", "sso-cache.test", "/me", "203.0.113.10", map[string]string{"Cookie": bob})
	if rr.Body.String() != "account for bob@example.com" || rr.Header().Get("X-Cache") == "HIT" {
		t.Fatalf("bob got %q (X-Cache %q), want his own uncached response", rr.Body.String(), rr.Header().Get("X-Cache"))
	}
}

// Q03: basic auth that the access list consumes (passAuth=false) is stripped
// before the cache runs; the request is still authenticated and not shareable.
func TestCacheBypassesStrippedBasicAuth(t *testing.T) {
	e, st := newTestEngine(t)
	var hits int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "render-%d", atomic.AddInt32(&hits, 1))
	})
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "users", Satisfy: "all", PassAuth: false,
		Users: []store.AccessUser{{Username: "alice", Password: "pw-alice"}, {Username: "bob", Password: "pw-bob"}}})
	cachedHost(t, st, "basic-cache.test", up, func(h *store.Host) { h.AccessListID = &aclID })
	reload(t, e)

	a := req(e, "GET", "basic-cache.test", "/", "203.0.113.9", map[string]string{"Authorization": basic("alice", "pw-alice")})
	b := req(e, "GET", "basic-cache.test", "/", "203.0.113.10", map[string]string{"Authorization": basic("bob", "pw-bob")})
	if a.Code != http.StatusOK || b.Code != http.StatusOK {
		t.Fatalf("auth: alice=%d bob=%d, want 200", a.Code, b.Code)
	}
	if b.Header().Get("X-Cache") == "HIT" || b.Body.String() == a.Body.String() {
		t.Fatalf("bob was served alice's cached response %q (X-Cache %q)", b.Body.String(), b.Header().Get("X-Cache"))
	}
}

// Q03: a compressed upstream body must never be replayed to a client that did
// not ask for compression.
func TestCacheVariesOnAcceptEncoding(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte("hello"))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
			return
		}
		fmt.Fprint(w, "hello")
	})
	cachedHost(t, st, "ae.test", up, nil)
	reload(t, e)

	gz := req(e, "GET", "ae.test", "/doc", "203.0.113.9", map[string]string{"Accept-Encoding": "gzip"})
	if gz.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("test setup: gzip client did not get a gzip body")
	}
	plain := req(e, "GET", "ae.test", "/doc", "203.0.113.10", nil)
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != "hello" {
		t.Fatalf("identity client got Content-Encoding %q body %q, want the plain body", plain.Header().Get("Content-Encoding"), plain.Body.String())
	}
	again := req(e, "GET", "ae.test", "/doc", "203.0.113.11", map[string]string{"Accept-Encoding": "gzip"})
	if again.Header().Get("X-Cache") != "HIT" || again.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("second gzip client: X-Cache %q Content-Encoding %q, want a gzip HIT", again.Header().Get("X-Cache"), again.Header().Get("Content-Encoding"))
	}
}

// Q03: request directives are honoured.
func TestCacheHonoursRequestDirectives(t *testing.T) {
	e, st := newTestEngine(t)
	var hits int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "render-%d", atomic.AddInt32(&hits, 1))
	})
	cachedHost(t, st, "dir.test", up, nil)
	reload(t, e)

	req(e, "GET", "dir.test", "/a", "203.0.113.9", nil) // primes /a
	if rr := req(e, "GET", "dir.test", "/a", "203.0.113.9", map[string]string{"Cache-Control": "no-cache"}); rr.Header().Get("X-Cache") == "HIT" {
		t.Fatal("request Cache-Control: no-cache was answered from the cache")
	}
	req(e, "GET", "dir.test", "/b", "203.0.113.9", map[string]string{"Cache-Control": "no-store"})
	if rr := req(e, "GET", "dir.test", "/b", "203.0.113.9", nil); rr.Header().Get("X-Cache") == "HIT" {
		t.Fatal("a response to a no-store request was stored")
	}
}

// Q03: max-age=0 means the origin considers the response stale immediately.
func TestCacheSkipsMaxAgeZero(t *testing.T) {
	e, st := newTestEngine(t)
	var hits int32
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=0")
		fmt.Fprintf(w, "render-%d", atomic.AddInt32(&hits, 1))
	})
	cachedHost(t, st, "stale.test", up, nil)
	reload(t, e)

	req(e, "GET", "stale.test", "/", "203.0.113.9", nil)
	if rr := req(e, "GET", "stale.test", "/", "203.0.113.9", nil); rr.Header().Get("X-Cache") == "HIT" {
		t.Fatalf("max-age=0 response was served from the cache (%q)", rr.Body.String())
	}
}
