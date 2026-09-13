package engine

import (
	"fmt"
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// A security dependency that disappears (a deleted access list, a path rule
// naming a gate the host does not have) must close the affected route, never
// fall back to something weaker. Routes are injected through SetDockerRoutes,
// which is the one path that reaches the engine without store validation, so
// this also covers rows that were broken before validation existed.

func TestMissingHostAccessListDenies(t *testing.T) {
	e, _ := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })
	missing := int64(999999)
	h := store.Host{Type: "proxy", Domains: []string{"gone.test"}, Upstream: up, CertMode: "none", Enabled: true, AccessListID: &missing}
	e.SetDockerRoutes([]store.Host{h}, nil)

	if rr := req(e, "GET", "gone.test", "/", "203.0.113.9", nil); rr.Code != http.StatusForbidden || rr.Body.String() == "backend" {
		t.Fatalf("host naming a missing access list: code=%d body=%q, want 403", rr.Code, rr.Body.String())
	}
}

func TestMissingPathAccessListDenies(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })
	missing := int64(999999)
	h := store.Host{Type: "proxy", Domains: []string{"path.test"}, Upstream: up, CertMode: "none", Enabled: true}
	h.Options.AuthRules = []store.AuthRule{{Path: "/private/", Mode: "accessList", AccessListID: &missing}}
	e.SetDockerRoutes([]store.Host{h}, nil)

	if rr := req(e, "GET", "path.test", "/private/data", "203.0.113.9", nil); rr.Code != http.StatusForbidden || rr.Body.String() == "backend" {
		t.Fatalf("path rule naming a missing access list: code=%d body=%q, want 403", rr.Code, rr.Body.String())
	}
	if rr := req(e, "GET", "path.test", "/open", "203.0.113.9", nil); rr.Code != http.StatusOK {
		t.Fatalf("unaffected path: got %d, want 200", rr.Code)
	}

	// The same through the store: a path access list that is deleted while
	// still referenced must not turn its path public after reload.
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	h2 := &store.Host{Type: "proxy", Domains: []string{"stored.test"}, Upstream: up}
	h2.Options.AuthRules = []store.AuthRule{{Path: "/private/", Mode: "accessList", AccessListID: &aclID}}
	mustCreateHost(t, st, h2)
	reload(t, e)
	if rr := req(e, "GET", "stored.test", "/private/x", "203.0.113.9", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("before delete: got %d, want 403", rr.Code)
	}
	_ = st.DeleteAccessList(aclID) // refused once references are checked; closed either way
	reload(t, e)
	if rr := req(e, "GET", "stored.test", "/private/x", "203.0.113.9", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("after deleting the referenced access list: got %d, want 403", rr.Code)
	}
}

// A path rule whose gate the host does not have (forward auth or SSO with no
// provider anywhere) must deny rather than borrow the host's own gate.
func TestPathRuleWithoutItsGateDenies(t *testing.T) {
	e, _ := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })
	h := store.Host{Type: "proxy", Domains: []string{"nogate.test"}, Upstream: up, CertMode: "none", Enabled: true}
	h.Options.AuthRules = []store.AuthRule{
		{Path: "/fa/", Mode: "forwardAuth"},
		{Path: "/sso/", Mode: "oidc"},
		{Path: "/weird/", Mode: "no-such-mode"},
	}
	e.SetDockerRoutes([]store.Host{h}, nil)

	for _, p := range []string{"/fa/x", "/sso/x", "/weird/x"} {
		if rr := req(e, "GET", "nogate.test", p, "203.0.113.9", nil); rr.Code != http.StatusForbidden || rr.Body.String() == "backend" {
			t.Fatalf("%s on a host without that gate: code=%d body=%q, want 403", p, rr.Code, rr.Body.String())
		}
	}
}
