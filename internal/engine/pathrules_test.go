package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// Regression tests for paths that mean one thing to a path rule and another
// to the upstream. secprobe_test.go covers the carve-out shape (a gated host
// with a public path); these cover the inverse, a public host with one gated
// subtree, which is the exposed one: a path the rule's string compare leaves
// outside /admin/ that the upstream normalises into it bypasses the gate.

// gatedSubtree makes a public host whose /admin/ is behind a LAN-only list,
// and records the paths its upstream receives.
func gatedSubtree(t *testing.T, e *Engine, st *store.Store, domain string) *[]string {
	t.Helper()
	var reached []string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		reached = append(reached, r.URL.Path)
		_, _ = w.Write([]byte("ok"))
	})
	lan := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	h := &store.Host{Type: "proxy", Domains: []string{domain}, Upstream: up}
	h.Options.AuthRules = []store.AuthRule{{Path: "/admin/", Mode: "accessList", AccessListID: &lan}}
	mustCreateHost(t, st, h)
	reload(t, e)
	return &reached
}

// Every one of these paths was forwarded to the upstream before the fix. They
// are refused with 400 before any rule or gate, like a dot segment.
func TestAmbiguousPathsCannotReachAGatedSubtree(t *testing.T) {
	e, st := newTestEngine(t)
	reached := gatedSubtree(t, e, st, "gated.test")
	outside := "203.0.113.9"

	for _, path := range []string{
		"//admin/secret",               // nginx and Apache merge the slashes
		"/admin//secret",               // the same, inside the gated subtree
		"/admin;x/secret",              // Tomcat strips the path parameter
		"/public/..;/admin/secret",     // the same, then resolves the dot segment
		"/public/%5c..%5cadmin/secret", // IIS reads the backslashes as slashes
		"/a/%252e%252e/b",              // a double-encoded dot segment
	} {
		*reached = nil
		rr := req(e, "GET", "gated.test", path, outside, nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", path, rr.Code)
		}
		if len(*reached) > 0 {
			t.Errorf("%s: reached the upstream as %v", path, *reached)
		}
	}

	// The gate itself, spelled plainly or with an encoded slash.
	for _, path := range []string{"/admin/secret", "/admin%2fsecret"} {
		if rr := req(e, "GET", "gated.test", path, outside, nil); rr.Code != http.StatusForbidden {
			t.Errorf("%s from outside: got %d, want 403", path, rr.Code)
		}
	}

	// The case of a path is left alone: /Admin/secret is another path to
	// quicgate and to most upstreams, and is public here like the rest of the
	// host. An upstream that ignores case needs that spelling gated too (or a
	// gate on the whole host); nothing here folds or rewrites the path.
	*reached = nil
	if rr := req(e, "GET", "gated.test", "/Admin/secret", outside, nil); rr.Code != http.StatusOK || len(*reached) != 1 || (*reached)[0] != "/Admin/secret" {
		t.Errorf("/Admin/secret: got %d, upstream saw %v; want 200 with the path as sent", rr.Code, *reached)
	}

	// Ordinary paths are untouched, from outside and from the LAN, and the
	// query string is not the path.
	for _, c := range []struct {
		path, ip string
		want     int
	}{
		{"/public/app.tar.gz", outside, http.StatusOK},
		{"/.well-known/acme-challenge/x", outside, http.StatusOK},
		{"/search?q=a%3Bb%2F%2Fc%5Cd%2525", outside, http.StatusOK},
		{"/admin/", "10.1.2.3", http.StatusOK},
		{"/admin/secret", "10.1.2.3", http.StatusOK},
	} {
		if rr := req(e, "GET", "gated.test", c.path, c.ip, nil); rr.Code != c.want {
			t.Errorf("%s from %s: got %d, want %d", c.path, c.ip, rr.Code, c.want)
		}
	}
}

// A host without path rules has no path-keyed decision to get past, and its
// clients keep such paths: the refusal is the price of a rule, not a new rule
// for every host.
func TestAmbiguousPathsPassOnHostsWithoutRules(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"plain.test"}, Upstream: up})
	reload(t, e)
	for _, path := range []string{"//x", "/a;b/c", "/a%255cb", "/a%5cb"} {
		if rr := req(e, "GET", "plain.test", path, "203.0.113.9", nil); rr.Code != http.StatusOK {
			t.Errorf("%s on a host without rules: got %d, want 200", path, rr.Code)
		}
	}
}

// A prefix rule covers its own subtree, not every path that starts with the
// same letters: a public /api leaves /api-internal behind the host's gate. A
// rule ending in "/" stays a plain prefix.
func TestPathRulesMatchWholeSegments(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	lan := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	h := &store.Host{Type: "proxy", Domains: []string{"seg.test"}, Upstream: up, AccessListID: &lan}
	h.Options.AuthRules = []store.AuthRule{{Path: "/api", Mode: "public"}, {Path: "/docs/", Mode: "public"}}
	mustCreateHost(t, st, h)
	reload(t, e)

	for _, c := range []struct {
		path string
		want int
	}{
		{"/api", http.StatusOK},
		{"/api/", http.StatusOK},
		{"/api/items", http.StatusOK},
		{"/api-internal", http.StatusForbidden},
		{"/api-internal/keys", http.StatusForbidden},
		{"/apix", http.StatusForbidden},
		{"/docs/", http.StatusOK},
		{"/docs/intro", http.StatusOK},
		{"/docs", http.StatusForbidden},
		{"/docsx", http.StatusForbidden},
	} {
		if rr := req(e, "GET", "seg.test", c.path, "203.0.113.9", nil); rr.Code != c.want {
			t.Errorf("%s from outside: got %d, want %d", c.path, rr.Code, c.want)
		}
	}
}

func TestPathWithin(t *testing.T) {
	for _, c := range []struct {
		p, prefix string
		want      bool
	}{
		{"/api", "/api", true},
		{"/api/", "/api", true},
		{"/api/x/y", "/api", true},
		{"/api-internal", "/api", false},
		{"/apix", "/api", false},
		{"/ap", "/api", false},
		{"/x/api", "/api", false},
		{"/api/x", "/api/", true},
		{"/api", "/api/", false},
		{"/", "/", true},
		{"/anything/at/all", "/", true},
	} {
		if got := pathWithin(c.p, c.prefix); got != c.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", c.p, c.prefix, got, c.want)
		}
	}
}

func TestHasAmbiguousSegment(t *testing.T) {
	for _, p := range []string{"//a", "/a//b", "/a//", `/a\b`, `/\`, "/a;b/c", "/..;/a", "/a/%2e%2e/b", "/a%", "/%"} {
		if !hasAmbiguousSegment(p) {
			t.Errorf("%q should be flagged", p)
		}
	}
	for _, p := range []string{"/", "/a/b/", "/a.b/c", "/.well-known/x", "/a-b_c~d", "/a:b@c", "/a,b+c", "/a b", "/über/ñ", "/a=b&c"} {
		if hasAmbiguousSegment(p) {
			t.Errorf("%q should be allowed", p)
		}
	}
}
