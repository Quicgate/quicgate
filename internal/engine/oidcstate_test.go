package engine

import (
	"net/http"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// The login state cookie is handed to every anonymous visitor, signed with the
// same key as the session cookie. Its JSON shares the session's host, expiry
// and provider fields, so without purpose binding it verified as a session with
// an empty identity and opened any host that admits every authenticated user.
func TestOIDCStateCookieIsNotASession(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("private")) })
	h := &store.Host{Type: "proxy", Domains: []string{"state.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid} // any authenticated user
	mustCreateHost(t, st, h)
	reload(t, e)

	first := req(e, "GET", "state.test", "/private", "203.0.113.9", nil)
	var state string
	for _, c := range first.Result().Cookies() {
		if c.Name == oidcStateName {
			state = c.Value
		}
	}
	if first.Code != http.StatusFound || state == "" {
		t.Fatalf("anonymous request: got %d and state cookie %q, want a 302 that sets one", first.Code, state)
	}

	rr := req(e, "GET", "state.test", "/private", "203.0.113.9",
		map[string]string{"Cookie": oidcSessionName + "=" + state})
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), idp.srv.URL) {
		t.Fatalf("state cookie presented as a session: got %d %q, want a 302 to the IdP", rr.Code, rr.Body.String())
	}

	// And the other way round: a real session is not a login in flight.
	idp.email = "user@example.com"
	session := oidcLogin(t, e, idp, "state.test")
	value := strings.TrimPrefix(session, oidcSessionName+"=")
	cb := req(e, "GET", "state.test", oidcCallbackPath+"?code=c1&state=", "203.0.113.9",
		map[string]string{"Cookie": oidcStateName + "=" + value})
	if cb.Code != http.StatusBadRequest {
		t.Fatalf("session cookie presented as login state: got %d %q, want 400", cb.Code, cb.Body.String())
	}
}
