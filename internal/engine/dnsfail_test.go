package engine

import (
	"fmt"
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// Q04 red tests that need no resolver seam: ".invalid" is reserved (RFC 6761)
// and never resolves, so it stands in for a dynamic-DNS name during an outage.

const unresolvableHost = "quicgate-review.invalid"

func TestUnresolvedAllowRuleDoesNotOpenList(t *testing.T) {
	c := compileAccess(store.AccessList{
		Name: "ddns", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", Host: unresolvableHost}},
	}, nil, nil, nil)
	if c.ipAllowed("203.0.113.9:1", "GET") {
		t.Fatal("an allow list whose only hostname failed to resolve admitted an outsider")
	}
}

func TestUnresolvedDenyRuleDoesNotWiden(t *testing.T) {
	c := compileAccess(store.AccessList{
		Name: "ddns-deny", Satisfy: "any",
		Rules: []store.AccessRule{
			{Action: "deny", Host: unresolvableHost},
			{Action: "allow", CIDR: "0.0.0.0/0"},
		},
	}, nil, nil, nil)
	if c.ipAllowed("203.0.113.9:1", "GET") {
		t.Fatal("a deny rule that failed to resolve was skipped, letting everyone through the allow-all below it")
	}
}

func TestCountryRuleWithoutGeoIPDoesNotWiden(t *testing.T) {
	c := compileAccess(store.AccessList{
		Name: "geo", Satisfy: "any",
		Rules: []store.AccessRule{
			{Action: "deny", Country: "RU"},
			{Action: "allow", CIDR: "0.0.0.0/0"},
		},
	}, nil, nil, nil)
	if c.ipAllowed("203.0.113.9:1", "GET") {
		t.Fatal("a deny-country rule with no GeoIP database was skipped, letting everyone through")
	}
}

// End to end: the host stays closed after a reload that cannot resolve.
func TestDNSFailureKeepsHostClosed(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") })
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "home", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", Host: unresolvableHost}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"ddns.test"}, Upstream: up, AccessListID: &aclID})
	reload(t, e)
	reload(t, e)

	if rr := req(e, "GET", "ddns.test", "/", "203.0.113.9", nil); rr.Code != http.StatusForbidden || rr.Body.String() == "backend" {
		t.Fatalf("outsider after an unresolvable reload: code=%d body=%q, want 403", rr.Code, rr.Body.String())
	}
}
