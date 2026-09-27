package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every JSON body is bounded (M-1): one byte over the limit is refused as 413
// before it is parsed, whether the handler decodes strictly (configuration)
// or loosely (credentials), and a body within the limit still works.
func TestRequestBodiesAreBounded(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	over := func(limit int) string { return `{"Email":"` + strings.Repeat("a", limit) + `"}` }
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(over(maxLoginBody))))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized login body: %d %s, want 413", rr.Code, rr.Body.String())
	}
	for _, path := range []string{"/api/hosts", "/api/import", "/api/custom-certs", "/api/wg/breakglass", "/api/custom-certs/self-signed"} {
		if rr := call(t, s, http.MethodPost, path, sess, over(maxJSONBody)); rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body on %s: %d %s, want 413", path, rr.Code, rr.Body.String())
		}
	}
	for _, path := range []string{"/api/password", "/api/email", "/api/2fa/disable", "/api/2fa/enable", "/api/tokens", "/api/wg/server-key/reset"} {
		if rr := call(t, s, http.MethodPost, path, sess, over(maxLoginBody)); rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body on %s: %d %s, want 413", path, rr.Code, rr.Body.String())
		}
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, over(maxJSONBody)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized settings body: %d, want 413", rr.Code)
	}
	// Within the limit, requests work as before.
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"acme_email": "ops@example.com"}); rr.Code != http.StatusOK {
		t.Fatalf("a normal body: %d %s", rr.Code, rr.Body.String())
	}
	// An empty body is still accepted where it was (2FA disable asks for the
	// password and reports that, not a decoding error).
	if rr := call(t, s, http.MethodPost, "/api/2fa/disable", sess, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("2FA disable without a body: %d %s, want 401", rr.Code, rr.Body.String())
	}
}
