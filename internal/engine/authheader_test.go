package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// The Authorization header is consumed only when the list checked it: a Basic
// credential that named one of its users, on a list that does not pass it on.
// A request admitted by its address keeps the header, whatever its scheme, so
// a bearer-token API behind a "LAN or password" list keeps working. Before,
// every list with users stripped the header from every request it admitted.
func TestAuthorizationStrippedOnlyWhenConsumed(t *testing.T) {
	e, st := newTestEngine(t)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	lanOrPassword := mustCreateACL(t, st, &store.AccessList{Name: "lan or password", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}},
		Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	passing := mustCreateACL(t, st, &store.AccessList{Name: "passing", Satisfy: "all", PassAuth: true,
		Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"api.test"}, Upstream: up, AccessListID: &lanOrPassword})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"pass.test"}, Upstream: up, AccessListID: &passing})
	reload(t, e)

	lan, outside := "10.1.2.3", "203.0.113.9"
	for _, c := range []struct {
		what, host, ip, auth string
		code                 int
		upstream             string
	}{
		{"a bearer token from the LAN passes through", "api.test", lan, "Bearer t0k3n", http.StatusOK, "Bearer t0k3n"},
		{"no credential from the LAN", "api.test", lan, "", http.StatusOK, ""},
		// Admitted by address, so the list did not consume the credential,
		// right or wrong: the upstream gets what the client sent.
		{"a wrong password from the LAN is not the list's to eat", "api.test", lan, basic("u", "wrong"), http.StatusOK, basic("u", "wrong")},
		{"the right password from the LAN is consumed", "api.test", lan, basic("u", "p"), http.StatusOK, ""},
		{"the right password from outside is consumed", "api.test", outside, basic("u", "p"), http.StatusOK, ""},
		{"a bearer token from outside admits nobody", "api.test", outside, "Bearer t0k3n", http.StatusUnauthorized, "unreached"},
		{"pass auth keeps the consumed credential", "pass.test", outside, basic("u", "p"), http.StatusOK, basic("u", "p")},
	} {
		seen = "unreached"
		var hdr map[string]string
		if c.auth != "" {
			hdr = map[string]string{"Authorization": c.auth}
		}
		rr := req(e, "GET", c.host, "/", c.ip, hdr)
		if rr.Code != c.code || seen != c.upstream {
			t.Errorf("%s: %d, upstream saw %q; want %d and %q", c.what, rr.Code, seen, c.code, c.upstream)
		}
	}
}
