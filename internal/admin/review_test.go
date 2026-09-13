package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

// ---- helpers ----

func mustUser(t *testing.T, s *Server, email, pw string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUser(email, string(hash), false); err != nil {
		t.Fatal(err)
	}
}

// login returns the session cookie value.
func login(t *testing.T, s *Server, email, pw string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"Email": email, "Password": pw})
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "qg_session" {
			return c.Value
		}
	}
	t.Fatal("login set no session cookie")
	return ""
}

func call(t *testing.T, s *Server, method, path, sess string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if sess != "" {
		req.AddCookie(&http.Cookie{Name: "qg_session", Value: sess})
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func sessionFrom(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "qg_session" && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

// ---- Q11: credential changes revoke live sessions ----

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "old-password-1")
	a := login(t, s, "admin@example.com", "old-password-1")
	b := login(t, s, "admin@example.com", "old-password-1")

	rr := call(t, s, http.MethodPost, "/api/password", a, map[string]string{"Current": "old-password-1", "New": "new-password-2"})
	if rr.Code != http.StatusOK {
		t.Fatalf("password change: %d %s", rr.Code, rr.Body.String())
	}
	if got := call(t, s, http.MethodGet, "/api/hosts", b, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("other session after a password change: got %d, want 401", got)
	}
	// The session that changed the password continues, on a fresh id.
	current := a
	if fresh := sessionFrom(rr); fresh != "" {
		current = fresh
		if got := call(t, s, http.MethodGet, "/api/hosts", a, nil).Code; got != http.StatusUnauthorized {
			t.Fatalf("old id of the changing session: got %d, want 401 once a fresh id was issued", got)
		}
	}
	if got := call(t, s, http.MethodGet, "/api/hosts", current, nil).Code; got != http.StatusOK {
		t.Fatalf("the session that changed the password: got %d, want 200", got)
	}
}

func TestTOTPChangeRequiresPassword(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.store.GetUserByEmail("admin@example.com")
	if err := s.store.SetTOTPSecret(u.ID, key.Secret()); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "password-123", "Code": code})
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	sess := sessionFrom(rr)
	if sess == "" {
		t.Fatalf("2FA login failed: %d %s", rr.Code, rr.Body.String())
	}

	if got := call(t, s, http.MethodPost, "/api/2fa/disable", sess, map[string]string{}).Code; got == http.StatusOK {
		t.Fatal("2FA was disabled by a session without re-entering the password")
	}
	if u, _ := s.store.GetUserByEmail("admin@example.com"); u.TOTPSecret == "" {
		t.Fatal("2FA secret removed without re-authentication")
	}
	if got := call(t, s, http.MethodPost, "/api/2fa/disable", sess, map[string]string{"Password": "wrong"}).Code; got == http.StatusOK {
		t.Fatal("2FA was disabled with a wrong password")
	}
	if got := call(t, s, http.MethodPost, "/api/2fa/disable", sess, map[string]string{"Password": "password-123"}).Code; got != http.StatusOK {
		t.Fatalf("2FA disable with the right password: got %d, want 200", got)
	}
}

// Q11: turning 2FA on also needs the password.
func TestTOTPEnableRequiresPassword(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	if got := call(t, s, http.MethodPost, "/api/2fa/enable", sess, map[string]string{"Secret": key.Secret(), "Code": code}).Code; got == http.StatusOK {
		t.Fatal("2FA was enabled without the password")
	}
	if u, _ := s.store.GetUserByEmail("admin@example.com"); u.TOTPSecret != "" {
		t.Fatal("a 2FA secret was stored without re-authentication")
	}
	if got := call(t, s, http.MethodPost, "/api/2fa/enable", sess, map[string]string{"Secret": key.Secret(), "Code": code, "Password": "password-123"}).Code; got != http.StatusOK {
		t.Fatalf("2FA enable with the password: got %d, want 200", got)
	}
}

// ---- Q12: admin OIDC login binds the transaction ----

type adminIdP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	email     string
	nonce     string // what the next id_token will carry
	challenge string // the S256 code_challenge of the login being finished
}

func newAdminIdP(t *testing.T) *adminIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &adminIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token",
			"jwks_uri": base + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// A real IdP refuses the code unless the verifier matches the challenge
		// sent with the authorization request; so does this one.
		vsum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if idp.challenge == "" || base64.RawURLEncoding.EncodeToString(vsum[:]) != idp.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{
			"iss": idp.srv.URL, "aud": "admin-client", "sub": "u1", "email": idp.email, "email_verified": true,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}
		if idp.nonce != "" {
			claims["nonce"] = idp.nonce
		}
		hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k"})
		payload, _ := json.Marshal(claims)
		signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(payload)
		sum := sha256.Sum256([]byte(signing))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer",
			"id_token": signing + "." + base64.RawURLEncoding.EncodeToString(sig)})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func adminOIDCServer(t *testing.T) (*Server, *adminIdP) {
	t.Helper()
	s := newTestServer(t)
	idp := newAdminIdP(t)
	for k, v := range map[string]string{
		"oidc_enabled": "1", "oidc_issuer": idp.srv.URL, "oidc_client_id": "admin-client",
		"oidc_client_secret": "s", "oidc_redirect_url": "https://admin.test/api/oidc/callback",
		"oidc_allowed_emails": "boss@example.com",
	} {
		if err := s.store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return s, idp
}

func startAdminOIDC(t *testing.T, s *Server) (*httptest.ResponseRecorder, *url.URL) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("admin OIDC login: %d %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return rr, loc
}

func adminCallback(s *Server, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/callback?code=c1&state="+url.QueryEscape(state), nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestAdminOIDCUsesPKCENonceAndSecureState(t *testing.T) {
	s, _ := adminOIDCServer(t)
	rr, loc := startAdminOIDC(t, s)
	q := loc.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("admin login redirect has no S256 PKCE challenge: %s", loc)
	}
	if q.Get("nonce") == "" {
		t.Fatalf("admin login redirect has no nonce: %s", loc)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "qg_oidc_state" && !c.Secure {
			t.Fatal("admin OIDC state cookie is not Secure on an HTTPS request")
		}
	}
}

func TestAdminOIDCCallbackIsOneUseAndChecksNonce(t *testing.T) {
	s, idp := adminOIDCServer(t)
	idp.email = "boss@example.com"

	rr, loc := startAdminOIDC(t, s)
	idp.nonce, idp.challenge = loc.Query().Get("nonce"), loc.Query().Get("code_challenge")
	cookies := rr.Result().Cookies()
	first := adminCallback(s, loc.Query().Get("state"), cookies)
	if first.Code != http.StatusFound || sessionFrom(first) == "" {
		t.Fatalf("first callback: %d %s, want a session", first.Code, first.Body.String())
	}
	replay := adminCallback(s, loc.Query().Get("state"), cookies)
	if replay.Code == http.StatusFound || sessionFrom(replay) != "" {
		t.Fatalf("replayed callback minted another session (%d)", replay.Code)
	}

	// An id_token carrying someone else's nonce is refused.
	rr, loc = startAdminOIDC(t, s)
	idp.nonce, idp.challenge = "a-nonce-from-another-login", loc.Query().Get("code_challenge")
	if got := adminCallback(s, loc.Query().Get("state"), rr.Result().Cookies()); got.Code == http.StatusFound || sessionFrom(got) != "" {
		t.Fatalf("callback with a mismatched nonce minted a session (%d)", got.Code)
	}
}

// ---- Q10: restore reproduces the backup ----

func backupArchive(t *testing.T, s *Server, sess string) []byte {
	t.Helper()
	rr := call(t, s, http.MethodGet, "/api/backup", sess, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

func TestRestoreRestoresTokensAndPortForwards(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	inBackup, err := s.store.CreateAPIToken("in-backup")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreatePortForward(&store.PortForward{ExtPort: 2350, Protocol: "tcp", IntIP: "192.168.1.5", IntPort: 2350, Label: "game", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	archive := backupArchive(t, s, sess)

	// Change the live state after the backup.
	list, _ := s.store.ListAPITokens()
	for _, tok := range list {
		_ = s.store.DeleteAPIToken(tok.ID)
	}
	later, err := s.store.CreateAPIToken("created-after-backup")
	if err != nil {
		t.Fatal(err)
	}
	pfs, _ := s.store.ListPortForwards()
	for _, p := range pfs {
		_ = s.store.DeletePortForward(p.ID)
	}

	rr := call(t, s, http.MethodPost, "/api/restore", sess, archive)
	if rr.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rr.Code, rr.Body.String())
	}
	if !s.store.ValidAPIToken(inBackup.Token) {
		t.Fatal("an API token that was in the backup is not valid after restore")
	}
	if s.store.ValidAPIToken(later.Token) {
		t.Fatal("an API token created after the backup survived the restore")
	}
	if pfs, _ := s.store.ListPortForwards(); len(pfs) != 1 || pfs[0].ExtPort != 2350 {
		t.Fatalf("port forwards after restore = %+v, want the one from the backup", pfs)
	}
}

func TestRestoreReportsCertificateCopyFailure(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	// A backup with a certificate file in it.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := s.store.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	db, _ := os.ReadFile(snap)
	for name, data := range map[string][]byte{"quicgate.db": db, "certs/acme/example/cert.crt": []byte("certificate")} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = gz.Close()

	// The live certs path is a file, so nothing can be written beneath it.
	if err := os.WriteFile(filepath.Join(s.dataDir, "certs"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := call(t, s, http.MethodPost, "/api/restore", sess, buf.Bytes())
	if rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), "restored") {
		t.Fatalf("restore reported success although the certificate could not be written: %s", rr.Body.String())
	}
}

// ---- Q09: import is all or nothing, and repeatable ----

func TestImportIsAtomic(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	doc := `{"hosts":[
		{"type":"proxy","domains":["good.test"],"certMode":"none","enabled":true,"upstream":{"scheme":"http","host":"127.0.0.1","port":8080}},
		{"type":"proxy","domains":["bad domain!"],"certMode":"none","enabled":true,"upstream":{"scheme":"http","host":"127.0.0.1","port":8080}}
	]}`
	if rr := call(t, s, http.MethodPost, "/api/import", sess, doc); rr.Code == http.StatusOK {
		t.Fatalf("import with an invalid host succeeded: %s", rr.Body.String())
	}
	if hosts, _ := s.store.ListHosts(); len(hosts) != 0 {
		t.Fatalf("a rejected import left %d host(s) stored", len(hosts))
	}
}

func TestImportIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	doc := `{"accessLists":[{"name":"lan","satisfy":"any","rules":[{"action":"allow","cidr":"10.0.0.0/8"}]}],
		"hosts":[{"type":"proxy","domains":["app.test"],"certMode":"none","enabled":true,"upstream":{"scheme":"http","host":"127.0.0.1","port":8080}}],
		"streams":[{"listenPort":2222,"protocol":"tcp","forwardHost":"127.0.0.1","forwardPort":22,"enabled":true}]}`
	for i := 0; i < 2; i++ {
		if rr := call(t, s, http.MethodPost, "/api/import", sess, doc); rr.Code != http.StatusOK {
			t.Fatalf("import run %d: %d %s", i+1, rr.Code, rr.Body.String())
		}
	}
	lists, _ := s.store.ListAccessLists()
	hosts, _ := s.store.ListHosts()
	streams, _ := s.store.ListStreams()
	if len(lists) != 1 || len(hosts) != 1 || len(streams) != 1 {
		t.Fatalf("after importing the same document twice: %d lists, %d hosts, %d streams, want 1 of each", len(lists), len(hosts), len(streams))
	}
}
