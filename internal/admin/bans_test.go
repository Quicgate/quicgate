package admin

import (
	"net/http"
	"strings"
	"testing"
)

// The ban list is behind admin authentication, is a JSON array even when
// empty, and unbanning validates the address.
func TestBansEndpoints(t *testing.T) {
	s := newTestServer(t)
	if rr := call(t, s, http.MethodGet, "/api/bans", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/bans: %d, want 401", rr.Code)
	}
	if rr := call(t, s, http.MethodDelete, "/api/bans/203.0.113.5", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous DELETE /api/bans: %d, want 401", rr.Code)
	}
	mustUser(t, s, "ops@example.com", "correct horse battery staple")
	sess := login(t, s, "ops@example.com", "correct horse battery staple")
	if rr := call(t, s, http.MethodGet, "/api/bans", sess, nil); rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Fatalf("GET /api/bans: %d %q, want 200 []", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodDelete, "/api/bans/not-an-ip", sess, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("DELETE a non-address: %d, want 400", rr.Code)
	}
	if rr := call(t, s, http.MethodDelete, "/api/bans/203.0.113.5", sess, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE an address that is not banned: %d, want 404", rr.Code)
	}
}
