package engine

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// vpnIdP is a synthetic identity provider for the portal: it issues refresh
// tokens and rotates them, states auth_time, serves UserInfo, and can be told
// to misbehave in the ways the design has to survive.
type vpnIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	mu  sync.Mutex

	sub, email   string
	groups       []string // nil: the claim is left out
	nonce        string
	authAge      time.Duration // how long ago the person authenticated
	omitAuthTime bool
	noRefresh    bool // the token response carries no refresh token
	// What a refresh does.
	refuse        bool // 400 invalid_grant: the account is gone
	unavailable   bool // 503
	omitIDToken   bool // a refresh response without an ID token (legal in OIDC)
	userinfoSub   string
	refreshes     int
	lastRefreshed string
	hold          chan struct{} // when set, a refresh waits here
	holding       chan struct{} // closed once a refresh is waiting
}

func newVPNIdP(t *testing.T) *vpnIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &vpnIdP{key: key, sub: "u1", email: "ann@example.com", groups: []string{"vpn-users"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token",
			"jwks_uri": base + "/keys", "userinfo_endpoint": base + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		refresh := r.Form.Get("grant_type") == "refresh_token"
		idp.mu.Lock()
		hold, holding := idp.hold, idp.holding
		idp.mu.Unlock()
		if refresh && hold != nil {
			close(holding)
			<-hold
		}
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if refresh {
			idp.lastRefreshed = r.Form.Get("refresh_token")
			switch {
			case idp.unavailable:
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
				return
			case idp.refuse:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"the account is disabled"}`))
				return
			}
			idp.refreshes++
		}
		out := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300}
		if !idp.noRefresh {
			out["refresh_token"] = fmt.Sprintf("rt-%d", idp.refreshes)
		}
		if !(refresh && idp.omitIDToken) {
			out["id_token"] = idp.idToken(t, refresh)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		sub := idp.sub
		if idp.userinfoSub != "" {
			sub = idp.userinfoSub
		}
		claims := map[string]any{"sub": sub, "email": idp.email}
		if idp.groups != nil {
			claims["groups"] = idp.groups
		}
		_ = json.NewEncoder(w).Encode(claims)
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (f *vpnIdP) idToken(t *testing.T, refresh bool) string {
	claims := map[string]any{
		"iss": f.srv.URL, "aud": "quicgate-vpn", "sub": f.sub,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": f.email, "email_verified": true,
	}
	if !refresh {
		claims["nonce"] = f.nonce
	}
	if !f.omitAuthTime {
		claims["auth_time"] = time.Now().Add(-f.authAge).Unix()
	}
	if f.groups != nil {
		claims["groups"] = f.groups
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	body, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *vpnIdP) set(fn func(*vpnIdP)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

const portalHost = "vpn.test"

type portalFixture struct {
	https    bool // requests arrive over TLS
	e        *Engine
	st       *store.Store
	idp      *vpnIdP
	provider int64
}

func newPortalFixture(t *testing.T, enrol ...store.VPNSubject) *portalFixture {
	t.Helper()
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	t.Cleanup(e.wg.Close)
	idp := newVPNIdP(t)
	p := &store.OIDCProvider{Name: "idp", Issuer: idp.srv.URL, ClientID: "quicgate-vpn", ClientSecret: "s3cret"}
	if err := st.CreateOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	if len(enrol) == 0 {
		enrol = []store.VPNSubject{{Kind: "group", Provider: p.ID, Group: "vpn-users"}}
	}
	for i := range enrol {
		enrol[i].Provider = p.ID
	}
	setSettings(t, st, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(freeUDP(t)), "wg_endpoint": "vpn.example.com:51820", "wg_devices_per_user": "2"})
	h := &store.Host{Type: "vpn-portal", Domains: []string{portalHost}, CertMode: "none", Enabled: true,
		Options: store.Options{Portal: &store.PortalOptions{ProviderID: p.ID, ClaimsSource: "id_token", Enrol: enrol}}}
	if err := st.CreateHost(h); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	return &portalFixture{e: e, st: st, idp: idp, provider: p.ID}
}

// do sends one request to the portal host, as a browser on that origin would.
func (f *portalFixture) do(method, path, cookies string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "http://"+portalHost+path, rd)
	r.Host = portalHost
	r.RemoteAddr = "203.0.113.9:50000"
	if cookies != "" {
		r.Header.Set("Cookie", cookies)
	}
	origin := "http://" + portalHost
	if f.https {
		r.TLS = &tls.ConnectionState{}
		origin = "https://" + portalHost
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
	}
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	rr := httptest.NewRecorder()
	f.e.serveHTTPS(rr, r)
	return rr
}

// login walks the portal's login and returns the session cookie, or the
// response of the callback when it refused.
func (f *portalFixture) login(t *testing.T) (string, *httptest.ResponseRecorder) {
	t.Helper()
	r1 := f.do(http.MethodGet, "/.qg/vpn/login", "", nil, nil)
	if r1.Code != http.StatusFound {
		t.Fatalf("login start: %d %s", r1.Code, r1.Body.String())
	}
	loc, err := url.Parse(r1.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), f.idp.srv.URL) {
		t.Fatalf("the login went to %q, want the identity provider", r1.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("max_age") != "900" || !strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatalf("the authorization request misses PKCE, a nonce, max_age or offline_access: %s", loc)
	}
	f.idp.set(func(i *vpnIdP) { i.nonce = q.Get("nonce") })
	r2 := f.do(http.MethodGet, "/.qg/vpn/callback?code=c1&state="+q.Get("state"), cookieHeader(r1), nil, nil)
	if r2.Code != http.StatusFound {
		return "", r2
	}
	return cookieHeader(r2), r2
}

func (f *portalFixture) me(t *testing.T, cookie string) map[string]any {
	t.Helper()
	rr := f.do(http.MethodGet, "/.qg/vpn/api/me", cookie, nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("me: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}

func randomWGKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (f *portalFixture) liveDevices() []wg.Device {
	devices, _ := f.e.wgDevices(time.Now(), true)
	return devices
}

// The portal end to end: a fresh login, an enrolment whose preshared key is
// returned once, the API's CSRF rules, the device limit, and that a person
// can only touch their own devices.
func TestPortalLoginAndEnrolment(t *testing.T) {
	f := newPortalFixture(t)
	if rr := f.do(http.MethodGet, "/.qg/vpn/api/me", "", nil, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("me without a login: %d, want 401", rr.Code)
	}
	if rr := f.do(http.MethodGet, "/", "", nil, nil); rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("the portal page: %d, CSP %q", rr.Code, rr.Header().Get("Content-Security-Policy"))
	}
	cookie, cb := f.login(t)
	if cookie == "" {
		t.Fatalf("login refused: %d %s", cb.Code, cb.Body.String())
	}
	for _, c := range cb.Result().Cookies() {
		if c.Name == portalCookie && (!c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "") {
			t.Fatalf("the session cookie is %+v, want HttpOnly, SameSite=Strict and host-only", c)
		}
	}
	me := f.me(t, cookie)
	if me["email"] != "ann@example.com" || me["lease"].(map[string]any)["live"] != true {
		t.Fatalf("me = %v", me)
	}
	if strings.Contains(fmt.Sprint(me), "rt-") {
		t.Fatal("the portal shows the refresh token")
	}

	// The transaction cookie is used once: replaying the callback fails.
	r1 := f.do(http.MethodGet, "/.qg/vpn/login", "", nil, nil)
	loc, _ := url.Parse(r1.Header().Get("Location"))
	f.idp.set(func(i *vpnIdP) { i.nonce = loc.Query().Get("nonce") })
	cbPath := "/.qg/vpn/callback?code=c1&state=" + loc.Query().Get("state")
	if rr := f.do(http.MethodGet, cbPath, cookieHeader(r1), nil, nil); rr.Code != http.StatusFound {
		t.Fatalf("second login: %d", rr.Code)
	}
	if rr := f.do(http.MethodGet, strings.Replace(cbPath, loc.Query().Get("state"), "forged", 1), cookieHeader(r1), nil, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("a callback with another state: %d, want 400", rr.Code)
	}
	if rr := f.do(http.MethodGet, cbPath, "", nil, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("a callback without the transaction cookie: %d, want 400", rr.Code)
	}

	// Enrolment.
	key := randomWGKey(t)
	for name, hdr := range map[string]map[string]string{
		"no Origin":           {"Origin": ""},
		"another Origin":      {"Origin": "https://evil.example"},
		"a look-alike Origin": {"Origin": "http://" + portalHost + ".evil.example"},
		"a form content type": {"Content-Type": "application/x-www-form-urlencoded"},
	} {
		if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "x", "publicKey": key}, hdr); rr.Code != http.StatusForbidden {
			t.Errorf("enrolment with %s: %d, want 403", name, rr.Code)
		}
	}
	rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "phone", "publicKey": key}, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("enrol: %d %s", rr.Code, rr.Body.String())
	}
	var dev store.WGDevice
	_ = json.Unmarshal(rr.Body.Bytes(), &dev)
	if dev.PresharedKey == "" || dev.Address == "" || dev.Kind != "sso" {
		t.Fatalf("enrolled device = %+v", dev)
	}
	if strings.Contains(fmt.Sprint(f.me(t, cookie)), dev.PresharedKey) {
		t.Fatal("the preshared key comes back after the enrolment")
	}
	live := f.liveDevices()
	if len(live) != 1 || live[0].ID != dev.ID || live[0].Until.IsZero() || live[0].Owner != "ann@example.com" {
		t.Fatalf("devices on the endpoint = %+v, want the new one with a deadline", live)
	}
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "clone", "publicKey": key}, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("the same key twice: %d, want 400", rr.Code)
	}
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "laptop", "publicKey": randomWGKey(t)}, nil); rr.Code != http.StatusCreated {
		t.Fatalf("second device: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "third", "publicKey": randomWGKey(t)}, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("a third device with a limit of two: %d, want 400", rr.Code)
	}

	// Someone else's device cannot be removed, whatever its id.
	other := store.WGDevice{Name: "bob's", Kind: "sso", PublicKey: randomWGKey(t), Enabled: true, Provider: f.provider, Sub: "u2", Email: "bob@example.com"}
	_, network, _, _ := WGSettings(f.st)
	if err := f.st.CreateWGDevice(&other, network, randomWGKey(t), 0); err != nil {
		t.Fatal(err)
	}
	if rr := f.do(http.MethodDelete, fmt.Sprintf("/.qg/vpn/api/devices/%d", other.ID), cookie, map[string]string{}, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("removing another person's device: %d, want 404", rr.Code)
	}
	if d, _ := f.st.GetWGDevice(other.ID); d.RevokedAt != "" {
		t.Fatal("another person's device was revoked")
	}
	if rr := f.do(http.MethodDelete, fmt.Sprintf("/.qg/vpn/api/devices/%d", dev.ID), cookie, map[string]string{}, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("removing my own device: %d", rr.Code)
	}
	// A revoked device never comes back, not even with a new login.
	if c2, _ := f.login(t); c2 == "" {
		t.Fatal("login after a revocation failed")
	}
	for _, d := range f.liveDevices() {
		if d.ID == dev.ID {
			t.Fatal("a login restored a revoked device")
		}
	}
}

// A login only counts when it is fresh, returns a refresh token, and belongs
// to someone who may have devices (S24, S54). A blocked owner stays out.
func TestPortalRefusesLoginsThatProveTooLittle(t *testing.T) {
	for name, tc := range map[string]struct {
		idp  func(*vpnIdP)
		want int
	}{
		"an authentication from an hour ago, answered from the browser session": {func(i *vpnIdP) { i.authAge = time.Hour }, http.StatusUnauthorized},
		"no auth_time claim":           {func(i *vpnIdP) { i.omitAuthTime = true }, http.StatusUnauthorized},
		"no refresh token":             {func(i *vpnIdP) { i.noRefresh = true }, http.StatusUnauthorized},
		"not in the group":             {func(i *vpnIdP) { i.groups = []string{"staff"} }, http.StatusForbidden},
		"no groups claim":              {func(i *vpnIdP) { i.groups = nil }, http.StatusForbidden},
		"a recent login, in the group": {func(i *vpnIdP) { i.authAge = 5 * time.Minute }, http.StatusFound},
	} {
		f := newPortalFixture(t)
		f.idp.set(tc.idp)
		cookie, cb := f.login(t)
		if cb.Code != tc.want {
			t.Errorf("%s: callback %d, want %d (%s)", name, cb.Code, tc.want, cb.Body.String())
		}
		sessions, _ := f.st.ListVPNSessions()
		if (tc.want == http.StatusFound) != (len(sessions) == 1 && cookie != "") {
			t.Errorf("%s: %d leases and cookie %q", name, len(sessions), cookie)
		}
		f.e.wg.Close()
	}

	f := newPortalFixture(t)
	if err := f.st.BlockVPNOwner(f.provider, "u1", "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	if cookie, cb := f.login(t); cookie != "" || cb.Code != http.StatusForbidden {
		t.Fatalf("a blocked owner logged in: %d", cb.Code)
	}
	if sessions, _ := f.st.ListVPNSessions(); len(sessions) != 0 {
		t.Fatal("a blocked owner got a lease")
	}
}

func (f *portalFixture) lease(t *testing.T) store.VPNSession {
	t.Helper()
	s, err := f.st.GetVPNSession(f.provider, "u1")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// enrolled logs in and enrols one device.
func (f *portalFixture) enrolled(t *testing.T) {
	t.Helper()
	cookie, cb := f.login(t)
	if cookie == "" {
		t.Fatalf("login: %d %s", cb.Code, cb.Body.String())
	}
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "phone", "publicKey": randomWGKey(t)}, nil); rr.Code != http.StatusCreated {
		t.Fatalf("enrol: %d %s", rr.Code, rr.Body.String())
	}
}

// Renewals (S44, S45): positive evidence extends the lease and nothing else
// does; a refusal ends it at once; an outage moves no deadline.
func TestLeaseRenewal(t *testing.T) {
	ctx := context.Background()

	t.Run("a renewal extends the lease, stores the rotated token and the new groups", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		before := f.lease(t)
		f.idp.set(func(i *vpnIdP) { i.groups = []string{"vpn-users", "admins"} })
		time.Sleep(10 * time.Millisecond)
		f.e.renewLease(ctx, before)
		after := f.lease(t)
		if !after.LeaseUntil.After(before.LeaseUntil) || after.Generation != before.Generation+1 || after.RefreshToken != "rt-1" || len(after.Groups) != 2 {
			t.Fatalf("after a renewal: %+v (before %+v)", after, before)
		}
		if f.idp.lastRefreshed != "rt-0" {
			t.Fatalf("the refresh used %q, want the stored token rt-0", f.idp.lastRefreshed)
		}
		if !after.HardUntil.Equal(before.HardUntil) {
			t.Fatal("a renewal moved the hard limit: only a fresh login may")
		}
	})

	t.Run("a refusal ends the lease at once and takes the devices off", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		f.idp.set(func(i *vpnIdP) { i.refuse = true })
		f.e.renewLease(ctx, f.lease(t))
		if s := f.lease(t); s.State != "lapsed" || s.RefreshToken != "" || s.Live(time.Now()) {
			t.Fatalf("after invalid_grant: %+v", s)
		}
		if live := f.liveDevices(); len(live) != 0 {
			t.Fatalf("devices of a refused owner are still on the endpoint: %+v", live)
		}
	})

	t.Run("an outage moves no deadline, and only then does the grace apply", func(t *testing.T) {
		f := newPortalFixture(t)
		setSettings(t, f.st, map[string]string{"wg_outage_grace_minutes": "30"})
		f.enrolled(t)
		before := f.lease(t)
		if !before.AccessUntil().Equal(before.LeaseUntil) {
			t.Fatal("the grace applies without any failure")
		}
		f.idp.set(func(i *vpnIdP) { i.unavailable = true })
		for i := 0; i < 3; i++ {
			f.e.renewLease(ctx, f.lease(t))
		}
		after := f.lease(t)
		if !after.LeaseUntil.Equal(before.LeaseUntil) || !after.GraceUntil.Equal(before.GraceUntil) || !after.HardUntil.Equal(before.HardUntil) {
			t.Fatalf("failed renewals moved a deadline: %+v -> %+v", before, after)
		}
		if after.State != "active" || !after.Transient || !after.AccessUntil().Equal(before.GraceUntil) {
			t.Fatalf("after an outage: %+v, want active, transient, access until the grace", after)
		}
		// The provider is back but refuses: the grace is over at once.
		f.idp.set(func(i *vpnIdP) { i.unavailable, i.refuse = false, true })
		f.e.renewLease(ctx, f.lease(t))
		if s := f.lease(t); s.State != "lapsed" {
			t.Fatalf("a refusal during the grace: %+v", s)
		}
	})

	t.Run("the lease never passes the hard limit, and admission has the deadline", func(t *testing.T) {
		f := newPortalFixture(t)
		setSettings(t, f.st, map[string]string{"wg_outage_grace_minutes": "60"})
		f.enrolled(t)
		s := f.lease(t)
		hard := time.Now().Add(90 * time.Second)
		s.HardUntil = hard
		f.e.renewLease(ctx, s)
		// renewLease keeps the session's own hard limit; the store has the old
		// one, so check what a renewal computes from a near limit directly.
		next := capLease(f.e.newLease(time.Now(), s))
		if next.LeaseUntil.After(hard) || next.GraceUntil.After(hard) {
			t.Fatalf("lease %v and grace %v pass the hard limit %v", next.LeaseUntil, next.GraceUntil, hard)
		}
		live := f.liveDevices()
		if len(live) != 1 || !live[0].Until.Equal(f.lease(t).AccessUntil()) {
			t.Fatalf("the device's deadline is %v, want the owner's %v", live, f.lease(t).AccessUntil())
		}
	})

	t.Run("another person's answer ends the lease", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		s := f.lease(t)
		f.idp.set(func(i *vpnIdP) { i.sub = "someone-else" })
		f.e.renewLease(ctx, s)
		if got := f.lease(t); got.State != "lapsed" {
			t.Fatalf("a refresh that answers for another subject: %+v", got)
		}
	})

	t.Run("a refresh without an ID token fails the id_token profile and works with userinfo", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		f.idp.set(func(i *vpnIdP) { i.omitIDToken = true })
		f.e.renewLease(ctx, f.lease(t))
		if s := f.lease(t); s.State != "lapsed" {
			t.Fatalf("id_token profile without an ID token: %+v", s)
		}

		g := newPortalFixture(t)
		hosts, _ := g.st.ListHosts()
		hosts[0].Options.Portal.ClaimsSource = "userinfo"
		if err := g.st.UpdateHost(&hosts[0]); err != nil {
			t.Fatal(err)
		}
		reload(t, g.e)
		g.enrolled(t)
		before := g.lease(t)
		g.idp.set(func(i *vpnIdP) { i.omitIDToken = true })
		time.Sleep(10 * time.Millisecond)
		g.e.renewLease(ctx, before)
		if s := g.lease(t); s.State != "active" || !s.LeaseUntil.After(before.LeaseUntil) {
			t.Fatalf("userinfo profile: %+v", s)
		}
		g.idp.set(func(i *vpnIdP) { i.userinfoSub = "someone-else" })
		g.e.renewLease(ctx, g.lease(t))
		if s := g.lease(t); s.State != "lapsed" {
			t.Fatalf("UserInfo for another subject: %+v", s)
		}
	})

	t.Run("without the groups claim a group member loses the devices, an any-user keeps them", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		f.idp.set(func(i *vpnIdP) { i.groups = nil })
		f.e.renewLease(ctx, f.lease(t))
		if s := f.lease(t); s.State != "active" || len(s.Groups) != 0 {
			t.Fatalf("a missing claim is the empty set, not a failure: %+v", s)
		}
		if live := f.liveDevices(); len(live) != 0 {
			t.Fatalf("no longer in the group, still on the endpoint: %+v", live)
		}
		g := newPortalFixture(t, store.VPNSubject{Kind: "any-user"})
		g.enrolled(t)
		g.idp.set(func(i *vpnIdP) { i.groups = nil })
		g.e.renewLease(ctx, g.lease(t))
		if live := g.liveDevices(); len(live) != 1 {
			t.Fatalf("an any-user owner lost the devices over a missing groups claim: %+v", live)
		}
	})

	t.Run("an admin who ends a session wins over a renewal in flight", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		s := f.lease(t)
		hold, holding := make(chan struct{}), make(chan struct{})
		f.idp.set(func(i *vpnIdP) { i.hold, i.holding = hold, holding })
		done := make(chan struct{})
		go func() { f.e.renewLease(ctx, s); close(done) }()
		<-holding // the refresh is at the provider
		if err := f.st.EndVPNSession(s.ID, "ended", 0); err != nil {
			t.Fatal(err)
		}
		close(hold) // and now it succeeds
		<-done
		if got := f.lease(t); got.State != "ended" || got.RefreshToken != "" || got.Live(time.Now()) {
			t.Fatalf("the renewal brought an ended session back: %+v", got)
		}
		if live := f.liveDevices(); len(live) != 0 {
			t.Fatal("devices of an ended session are on the endpoint")
		}
	})

	t.Run("a blocked owner's devices are off, and a login does not bring them back", func(t *testing.T) {
		f := newPortalFixture(t)
		f.enrolled(t)
		if err := f.st.BlockVPNOwner(f.provider, "u1", "ann@example.com"); err != nil {
			t.Fatal(err)
		}
		if live := f.liveDevices(); len(live) != 0 {
			t.Fatal("a blocked owner's devices are on the endpoint")
		}
		if cookie, _ := f.login(t); cookie != "" {
			t.Fatal("a blocked owner logged in")
		}
		if live := f.liveDevices(); len(live) != 0 {
			t.Fatal("a login undid a block")
		}
	})
}

// Groups are only ever compared together with their identity provider (S53).
func TestSubjectsNameTheirProvider(t *testing.T) {
	admins1 := store.VPNSubject{Kind: "group", Provider: 1, Group: "admins"}
	if !subjectMatchesOwner(admins1, 1, "u1", []string{"admins"}) {
		t.Fatal("a member of the provider's group does not match")
	}
	if subjectMatchesOwner(admins1, 2, "u1", []string{"admins"}) {
		t.Fatal(`"admins" from another provider satisfied a subject about provider 1`)
	}
	if subjectMatchesOwner(store.VPNSubject{Kind: "any-user", Provider: 1}, 2, "u1", nil) {
		t.Fatal("any-user of provider 1 matched a user of provider 2")
	}
	if !subjectMatchesOwner(store.VPNSubject{Kind: "any-user", Provider: 1}, 1, "u1", nil) {
		t.Fatal("any-user needs no group")
	}
	e, _ := newTestEngine(t)
	owners := map[int64]vpnOwner{7: {provider: 2, sub: "u1", groups: map[string]bool{"admins": true}}}
	e.vpnOwners.Store(&owners)
	if e.vpnSubjectMatches(admins1, wg.Peer{Key: "device:7", ID: 7}) {
		t.Fatal(`a device of provider 2's "admins" satisfied a VPN rule about provider 1's`)
	}
	if !e.vpnSubjectMatches(store.VPNSubject{Kind: "group", Provider: 2, Group: "admins"}, wg.Peer{Key: "device:7", ID: 7}) {
		t.Fatal("the right provider's group does not match")
	}
	if e.vpnSubjectMatches(store.VPNSubject{Kind: "any-user", Provider: 2}, wg.Peer{Key: "site:7", Site: true, ID: 7}) {
		t.Fatal("a site matched a subject about a person")
	}
}

// There is no portal over plain HTTP (QG-05). It hands out a session and a
// device's configuration with its preshared key, and it serves the page that
// makes the private key: on plain HTTP anybody on the path gets all three.
func TestPortalNeedsHTTPS(t *testing.T) {
	f := newPortalFixture(t)
	f.e.cfg.DisableTLS = false // an ordinary instance, not the development mode of the other tests

	if rr := f.do(http.MethodGet, "/", "", nil, nil); rr.Code != http.StatusPermanentRedirect || rr.Header().Get("Location") != "https://"+portalHost+"/" {
		t.Fatalf("the page over plain HTTP: %d to %q, want a redirect to HTTPS", rr.Code, rr.Header().Get("Location"))
	}
	rr := f.do(http.MethodGet, "/.qg/vpn/login", "", nil, nil)
	if rr.Code != http.StatusPermanentRedirect || len(rr.Result().Cookies()) != 0 || strings.Contains(rr.Header().Get("Location"), f.idp.srv.URL) {
		t.Fatalf("a login started over plain HTTP: %d, cookies %v, to %q", rr.Code, rr.Result().Cookies(), rr.Header().Get("Location"))
	}
	// A header anybody can send does not make the connection encrypted.
	if rr := f.do(http.MethodGet, "/.qg/vpn/login", "", nil, map[string]string{"X-Forwarded-Proto": "https"}); rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("X-Forwarded-Proto from a stranger was believed: %d", rr.Code)
	}

	// Over HTTPS the portal works, and its cookies are Secure.
	f.https = true
	cookie, cb := f.login(t)
	if cookie == "" {
		t.Fatalf("login over HTTPS refused: %d %s", cb.Code, cb.Body.String())
	}
	for _, c := range cb.Result().Cookies() {
		if c.Value != "" && !c.Secure {
			t.Errorf("cookie %s is not Secure", c.Name)
		}
	}
	// The session is worth nothing over plain HTTP: no enrolment, no reading.
	f.https = false
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "phone", "publicKey": randomWGKey(t)}, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("an enrolment over plain HTTP: %d %s, want 403", rr.Code, rr.Body.String())
	}
	if rr := f.do(http.MethodGet, "/.qg/vpn/api/me", cookie, nil, nil); rr.Code == http.StatusOK {
		t.Fatalf("the API answered over plain HTTP: %s", rr.Body.String())
	}
	if n := f.deviceCount(t); n != 0 {
		t.Fatalf("%d devices were enrolled over plain HTTP", n)
	}
	f.https = true
	if rr := f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "phone", "publicKey": randomWGKey(t)}, nil); rr.Code != http.StatusCreated {
		t.Fatalf("an enrolment over HTTPS: %d %s", rr.Code, rr.Body.String())
	}
}

// Adding a device takes a login that is fresh now (QG-08). The page's session
// slides with use, and the lease is renewed in the background for weeks:
// neither says the person authenticated recently.
func TestEnrolmentNeedsAFreshLogin(t *testing.T) {
	f := newPortalFixture(t)
	cookie, cb := f.login(t)
	if cookie == "" {
		t.Fatalf("login refused: %d %s", cb.Code, cb.Body.String())
	}
	add := func() *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/.qg/vpn/api/devices", cookie, map[string]string{"name": "phone", "publicKey": randomWGKey(t)}, nil)
	}
	if rr := add(); rr.Code != http.StatusCreated {
		t.Fatalf("right after the login: %d %s", rr.Code, rr.Body.String())
	}
	// A day later the page is still open, the lease was renewed all along.
	f.e.portal.mu.Lock()
	for id, s := range f.e.portal.sessions {
		s.authTime = s.authTime.Add(-24 * time.Hour)
		f.e.portal.sessions[id] = s
	}
	f.e.portal.mu.Unlock()
	if me := f.me(t, cookie); me["lease"].(map[string]any)["live"] != true {
		t.Fatalf("the lease should still be live: %v", me)
	}
	if rr := add(); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "fresh login") {
		t.Fatalf("a day after the login: %d %s, want 401", rr.Code, rr.Body.String())
	}
	if n := f.deviceCount(t); n != 1 {
		t.Fatalf("%d devices, want the one from the fresh login", n)
	}
	// Logging in again brings enrolment back.
	cookie, _ = f.login(t)
	if rr := add(); rr.Code != http.StatusCreated {
		t.Fatalf("after a new login: %d %s", rr.Code, rr.Body.String())
	}
}

func (f *portalFixture) deviceCount(t *testing.T) int {
	t.Helper()
	all, err := f.st.ListWGDevices()
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}
