package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// The SSO cookie signing key follows the server key's rule (QG-04): a stored
// key this instance cannot open is kept as it is, single sign-on closes and
// says why, and the key works again, with every session signed by it, the
// moment the right sealing key is back. quicgate used to read "cannot open" as
// "not set" and made a new key over it, after which the right sealing key could
// no longer bring the old one, or anybody's session, back.
func TestAnUnreadableSSOKeyIsNeverReplaced(t *testing.T) {
	t.Setenv("QG_SECRET_KEY_FILE", "")
	keyA, keyB := sealKey(t), sealKey(t)
	dir := t.TempDir()
	idp := newFakeIdP(t)
	idp.email = "anna@example.com"
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ssoHost := func(t *testing.T, e *Engine, st *store.Store) {
		t.Helper()
		pid := mustCreateOIDCProvider(t, st, idp)
		h := &store.Host{Type: "proxy", Domains: []string{"key.test"}, Upstream: up}
		h.Options.OIDC = &store.OIDCAuth{ProviderID: pid}
		mustCreateHost(t, st, h)
		reload(t, e)
	}

	t.Setenv("QG_SECRET_KEY", keyA)
	e, st := openEngineAt(t, dir)
	ssoHost(t, e, st)
	session := oidcLogin(t, e, idp, "key.test")
	sealedBefore := rawSetting(t, e, "sso_cookie_secret")
	closeEngine(e, st)

	// The same database under another sealing key: what a restore onto a new
	// machine looks like. Nothing is minted, nothing verifies, nothing is
	// replaced, whatever happens.
	t.Setenv("QG_SECRET_KEY", keyB)
	e, st = openEngineAt(t, dir)
	for i := 0; i < 3; i++ {
		reload(t, e)
	}
	rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": session})
	if rr.Code != http.StatusServiceUnavailable || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("with a signing key it cannot open: %d %q, cookies %v; want 503 and nothing minted", rr.Code, rr.Body.String(), rr.Result().Cookies())
	}
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", nil); rr.Code != http.StatusServiceUnavailable || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("a login was started without a key: %d, cookies %v", rr.Code, rr.Result().Cookies())
	}
	if got := rawSetting(t, e, "sso_cookie_secret"); got != sealedBefore {
		t.Fatal("the stored signing key was replaced although it could not be read")
	}
	closeEngine(e, st)

	// The right sealing key comes back: so does every session.
	t.Setenv("QG_SECRET_KEY", keyA)
	e, st = openEngineAt(t, dir)
	reload(t, e)
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": session}); rr.Code != http.StatusOK {
		t.Fatalf("with the original sealing key the session is refused: %d %q", rr.Code, rr.Body.String())
	}
	closeEngine(e, st)

	// A fresh installation still makes its key, and a cleared key (the
	// documented way to sign everyone out) is replaced by a new one.
	t.Setenv("QG_SECRET_KEY", keyB)
	e, st = openEngineAt(t, t.TempDir())
	defer closeEngine(e, st)
	ssoHost(t, e, st)
	fresh := oidcLogin(t, e, idp, "key.test")
	if st.GetSetting("sso_cookie_secret", "") == "" {
		t.Fatal("a fresh installation made no signing key")
	}
	if err := st.SetSetting("sso_cookie_secret", ""); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	if rr := req(e, "GET", "key.test", "/app", "203.0.113.9", map[string]string{"Cookie": fresh}); rr.Code != http.StatusFound {
		t.Fatalf("a session signed with the cleared key: %d, want a redirect to the provider", rr.Code)
	}
	if next := oidcLogin(t, e, idp, "key.test"); next == fresh {
		t.Fatal("the new session is signed like the old one")
	}
}
