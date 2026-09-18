package admin

import (
	"net/http"
	"strings"
	"testing"
)

// A never-ban list with a typo is refused whole, and the own addresses can be
// read back so the setting is not a black box.
func TestSettingsNeverBanList(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"ban_exempt": "192.0.2.1\n203.0.113"})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "203.0.113") {
		t.Fatalf("a list with a typo: got %d %s, want 400 naming the entry", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("ban_exempt", ""); got != "" {
		t.Fatalf("a refused list was stored: %q", got)
	}
	rr = call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"ban_exempt": "192.0.2.1\n2001:db8::/48", "ban_exempt_own": "1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("a valid list: got %d %s, want 200", rr.Code, rr.Body.String())
	}

	if rr := call(t, s, http.MethodGet, "/api/own-addresses", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("own addresses without a session: got %d, want 401", rr.Code)
	}
	if rr := call(t, s, http.MethodGet, "/api/own-addresses", sess, nil); rr.Code != http.StatusOK || !strings.HasPrefix(strings.TrimSpace(rr.Body.String()), "[") {
		t.Fatalf("own addresses: got %d %s, want a JSON list", rr.Code, rr.Body.String())
	}
}
