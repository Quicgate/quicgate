package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"quicgate/internal/store"
)

// GET stays public while other verbs fall through to deny (Pangolin #1408).
func TestMethodScopedRules(t *testing.T) {
	c := compileAccess(store.AccessList{
		Name: "t", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "0.0.0.0/0", Methods: []string{"GET", "HEAD"}}},
	}, nil, nil, nil)

	if !c.ipAllowed("1.2.3.4:9", "GET") {
		t.Fatal("GET should be allowed by the GET/HEAD rule")
	}
	if c.ipAllowed("1.2.3.4:9", "POST") {
		t.Fatal("POST must not match a GET/HEAD-scoped rule (no match -> deny)")
	}
}

// A CORS preflight carries no credentials by spec, so it skips the credential
// half of a list (Pangolin #2369) but never its network rules: those do not
// depend on credentials, and an allowlist must keep a private backend
// unreachable to everyone else, preflights included. The rules are evaluated
// for the method the preflight announces.
func TestCORSPreflightSkipsCredentialsNotNetworkRules(t *testing.T) {
	serve := func(c *compiledAccess, ip, announced string) bool {
		reached := false
		h := c.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
		pf := httptest.NewRequest(http.MethodOptions, "/", nil)
		pf.RemoteAddr = ip + ":1"
		pf.Header.Set("Access-Control-Request-Method", announced)
		h.ServeHTTP(httptest.NewRecorder(), pf)
		return reached
	}
	users := []store.AccessUser{{Username: "u", Hash: "$2a$10$invalidinvalidinvalidinvalidinvali"}}

	cidr := compileAccess(store.AccessList{Name: "cidr", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}, nil, nil, nil)
	if serve(cidr, "203.0.113.5", "POST") {
		t.Fatal("a preflight from outside an IP allowlist reached the backend")
	}
	if !serve(cidr, "10.1.2.3", "POST") {
		t.Fatal("a preflight from inside the allowlist was blocked")
	}

	credsOnly := compileAccess(store.AccessList{Name: "creds", Satisfy: "all", Users: users}, nil, nil, nil)
	if !serve(credsOnly, "203.0.113.5", "POST") {
		t.Fatal("a preflight was blocked by a credential-only list")
	}

	anyOf := compileAccess(store.AccessList{Name: "any", Satisfy: "any", Users: users,
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}, nil, nil, nil)
	if !serve(anyOf, "203.0.113.5", "POST") {
		t.Fatal("satisfy any: the real request may authenticate from anywhere, so its preflight must pass")
	}

	allOf := compileAccess(store.AccessList{Name: "all", Satisfy: "all", Users: users,
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}, nil, nil, nil)
	if serve(allOf, "203.0.113.5", "POST") {
		t.Fatal("satisfy all: a preflight from outside the network rules reached the backend")
	}

	publicGET := compileAccess(store.AccessList{Name: "get", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "0.0.0.0/0", Methods: []string{"GET"}}}}, nil, nil, nil)
	if !serve(publicGET, "203.0.113.5", "GET") {
		t.Fatal("a preflight for a publicly allowed GET was blocked")
	}
	if serve(publicGET, "203.0.113.5", "POST") {
		t.Fatal("a preflight for a POST the list denies reached the backend")
	}
}
