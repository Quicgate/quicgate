package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// Regression tests for the ways an auth layer gets walked around. Each of
// these failed before the fix that accompanies it.

// A public path carve-out must not become a tunnel to the rest of the host:
// quicgate matched /public/../secret as public while the upstream would have
// resolved it to /secret.
func TestTraversalCannotEscapeAPublicRule(t *testing.T) {
	e, st := newTestEngine(t)
	reached := false
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Write([]byte("upstream reached"))
	})
	id := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	h := &store.Host{Type: "proxy", Domains: []string{"trav.test"}, Upstream: up, AccessListID: &id}
	h.Options.AuthRules = []store.AuthRule{{Path: "/public/", Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	for _, path := range []string{
		"/public/../secret",
		"/public/%2e%2e/secret",
		"/public/./../secret",
		"/public/..",
	} {
		reached = false
		rr := req(e, "GET", "trav.test", path, "203.0.113.9", nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", path, rr.Code)
		}
		if reached {
			t.Errorf("%s: reached the upstream", path)
		}
	}
	// The legitimate public path and dotted filenames still work.
	if rr := req(e, "GET", "trav.test", "/public/app.tar.gz", "203.0.113.9", nil); rr.Code != http.StatusOK {
		t.Errorf("normal public path: got %d, want 200", rr.Code)
	}
	// ACME challenges live under a dot-prefixed directory, which is not a dot
	// segment and must keep working.
	if rr := req(e, "GET", "trav.test", "/public/.well-known/x", "203.0.113.9", nil); rr.Code != http.StatusOK {
		t.Errorf("/.well-known path: got %d, want 200", rr.Code)
	}
}

// A forward-auth host must not pass a client-supplied identity header through
// when the auth server itself does not set one.
func TestForwardAuthStripsSpoofedIdentity(t *testing.T) {
	e, st := newTestEngine(t)
	var sawUser string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		sawUser = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	var authSawUser string
	auth := backend(t, func(w http.ResponseWriter, r *http.Request) {
		authSawUser = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"fa.test"}, Upstream: up}
	h.Options.ForwardAuth = &store.ForwardAuth{
		URL:             "http://" + hostPort(auth.Host, auth.Port) + "/verify",
		ResponseHeaders: []string{"Remote-User"},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	req(e, "GET", "fa.test", "/", "203.0.113.9", map[string]string{"Remote-User": "spoofed@evil"})
	if sawUser != "" {
		t.Errorf("upstream saw spoofed Remote-User %q", sawUser)
	}
	if authSawUser != "" {
		t.Errorf("auth server saw spoofed Remote-User %q", authSawUser)
	}
}

// When the auth server does supply the header, it reaches the upstream.
func TestForwardAuthPassesRealIdentity(t *testing.T) {
	e, st := newTestEngine(t)
	var sawUser string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		sawUser = r.Header.Get("Remote-User")
		w.WriteHeader(http.StatusOK)
	})
	auth := backend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Remote-User", "real@example.com")
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"fa2.test"}, Upstream: up}
	h.Options.ForwardAuth = &store.ForwardAuth{
		URL:             "http://" + hostPort(auth.Host, auth.Port) + "/verify",
		ResponseHeaders: []string{"Remote-User"},
	}
	mustCreateHost(t, st, h)
	reload(t, e)

	req(e, "GET", "fa2.test", "/", "203.0.113.9", map[string]string{"Remote-User": "spoofed@evil"})
	if sawUser != "real@example.com" {
		t.Errorf("upstream saw Remote-User %q, want the auth server's value", sawUser)
	}
}

// TLS often terminates on a load balancer in front of quicgate; the session
// cookie must still be marked Secure there, or it rides plain HTTP hops.
func TestSessionCookieSecureBehindTerminatingProxy(t *testing.T) {
	g := &oidcGate{engine: &engineOIDC{secret: func() []byte { return make([]byte, 32) }}}
	r, _ := http.NewRequest("GET", "http://app.test/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	rec := &headerRecorder{h: http.Header{}}
	g.setCookie(rec, r, oidcSessionName, "v", 60)
	if sc := rec.h.Get("Set-Cookie"); !containsFold(sc, "; Secure") {
		t.Errorf("cookie lacks Secure behind an https-terminating proxy: %q", sc)
	}
}

type headerRecorder struct{ h http.Header }

func (h *headerRecorder) Header() http.Header       { return h.h }
func (h *headerRecorder) Write([]byte) (int, error) { return 0, nil }
func (h *headerRecorder) WriteHeader(int)           {}

func containsFold(s, sub string) bool {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestHasDotSegment(t *testing.T) {
	for _, p := range []string{"/a/../b", "/..", "/a/./b", "/./a", "/a/.."} {
		if !hasDotSegment(p) {
			t.Errorf("%q should be flagged", p)
		}
	}
	for _, p := range []string{"/", "/a/b", "/.well-known/acme-challenge/x", "/file.tar.gz", "/a..b/c", "/...", "/a/...b"} {
		if hasDotSegment(p) {
			t.Errorf("%q should be allowed", p)
		}
	}
}
