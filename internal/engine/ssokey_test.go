package engine

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// Q11: replacing or clearing the SSO cookie signing key takes effect on the
// next reload, so every session signed with the old key stops working without a
// restart (the documented way to sign everybody out).
func TestSSOSigningKeyChangeAppliesOnReload(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	idp.email = "gijs@example.com"
	pid := mustCreateOIDCProvider(t, st, idp)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := &store.Host{Type: "proxy", Domains: []string{"key.test"}, Upstream: up}
	h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
	mustCreateHost(t, st, h)
	reload(t, e)

	cookie := oidcLoginAt(t, e, idp, "key.test", "/app")
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": cookie}); rr.Code != http.StatusOK {
		t.Fatalf("session before rotation: got %d, want 200", rr.Code)
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := st.SetSetting("sso_cookie_secret", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": cookie}); rr.Code != http.StatusFound {
		t.Fatalf("session signed with the replaced key: got %d, want a 302 back to the IdP", rr.Code)
	}

	// Clearing the key also signs everyone out: a fresh key is generated.
	fresh := oidcLoginAt(t, e, idp, "key.test", "/app")
	if err := st.SetSetting("sso_cookie_secret", ""); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": fresh}); rr.Code != http.StatusFound {
		t.Fatalf("session after clearing the key: got %d, want a 302 back to the IdP", rr.Code)
	}
	if st.GetSetting("sso_cookie_secret", "") == "" {
		t.Fatal("no new signing key was persisted after the old one was cleared")
	}
}
