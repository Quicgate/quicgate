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
	}, nil, nil)

	if !c.ipAllowed("1.2.3.4:9", "GET") {
		t.Fatal("GET should be allowed by the GET/HEAD rule")
	}
	if c.ipAllowed("1.2.3.4:9", "POST") {
		t.Fatal("POST must not match a GET/HEAD-scoped rule (no match -> deny)")
	}
}

// A CORS preflight bypasses the gate even when the real request is blocked
// (Pangolin #2369); the real request stays gated.
func TestCORSPreflightBypassesGate(t *testing.T) {
	c := compileAccess(store.AccessList{
		Name: "t", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}},
	}, nil, nil)
	reached := false
	h := c.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// real POST from a non-allowed IP is denied
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.5:1"
	h.ServeHTTP(rr, req)
	if reached || rr.Code == http.StatusOK {
		t.Fatalf("real POST from blocked IP should be denied, got %d", rr.Code)
	}

	// preflight from the same blocked IP passes through to the backend
	reached = false
	pf := httptest.NewRequest(http.MethodOptions, "/", nil)
	pf.RemoteAddr = "203.0.113.5:1"
	pf.Header.Set("Access-Control-Request-Method", "POST")
	h.ServeHTTP(httptest.NewRecorder(), pf)
	if !reached {
		t.Fatal("CORS preflight should bypass the access gate")
	}
}
