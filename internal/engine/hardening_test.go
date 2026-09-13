package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"quicgate/internal/store"
)

// A ban notification goes to a webhook, which can be slow or unreachable. It
// must never be sent while the ban lock is held: every request on every host
// takes that lock, so a slow webhook froze all traffic for each ban.
func TestBanNotificationDoesNotStallTraffic(t *testing.T) {
	e, st := newTestEngine(t)
	hit, release := make(chan struct{}), make(chan struct{})
	var once bool
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !once {
			once = true
			close(hit)
		}
		<-release
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	for k, v := range map[string]string{"ban_enabled": "1", "ban_threshold": "2", "notify_url": slow.URL} {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "auth", Satisfy: "all", Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"locked.test"}, Upstream: up, AccessListID: &id})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"public.test"}, Upstream: up})
	reload(t, e)

	h := e.ban.wrap(e.serveHTTPS)
	do := func(host, ip string, hdr map[string]string) int {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.Host, r.RemoteAddr = host, ip+":40000"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h(rr, r)
		return rr.Code
	}
	go func() {
		for i := 0; i < 2; i++ {
			do("locked.test", "198.51.100.1", map[string]string{"Authorization": basic("u", "wrong")})
		}
	}()
	select {
	case <-hit:
	case <-time.After(5 * time.Second):
		t.Fatal("the ban never sent its notification")
	}
	done := make(chan int, 1)
	go func() { done <- do("public.test", "192.0.2.50", nil) }()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("unrelated request: got %d, want 200", code)
		}
	case <-time.After(time.Second):
		t.Fatal("an unrelated request waited on the ban notification")
	}
}

// The auto-ban configuration is compiled at reload, like every other setting,
// instead of being read from the database on every request (which also made
// every request wait for any write transaction in progress).
func TestBanConfigurationAppliesAtReload(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "auth", Satisfy: "all", Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"locked.test"}, Upstream: up, AccessListID: &id})
	reload(t, e)

	h := e.ban.wrap(e.serveHTTPS)
	fail := func() int {
		r := httptest.NewRequest("GET", "http://locked.test/", nil)
		r.RemoteAddr = "198.51.100.7:40000"
		r.Header.Set("Authorization", basic("u", "wrong"))
		rr := httptest.NewRecorder()
		h(rr, r)
		return rr.Code
	}
	// Written to the store but not applied yet: the running configuration
	// (auto-ban off) still holds.
	for k, v := range map[string]string{"ban_enabled": "1", "ban_threshold": "1"} {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fail()
	if code := fail(); code != http.StatusUnauthorized {
		t.Fatalf("before the reload: got %d, want 401 (auto-ban not applied yet)", code)
	}
	reload(t, e)
	fail()
	if code := fail(); code != http.StatusForbidden {
		t.Fatalf("after the reload: got %d, want 403 (banned)", code)
	}
}

// Identity headers are stripped whatever their spelling: many application
// servers (CGI, PHP, WSGI, Rack) fold Remote_User and Remote-User into the same
// variable, so an underscore variant is the same forged identity.
func TestIdentityHeaderVariantsAreStripped(t *testing.T) {
	e, st := newTestEngine(t)
	idp := newFakeIdP(t)
	pid := mustCreateOIDCProvider(t, st, idp)
	var seen http.Header
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	h := &store.Host{Type: "proxy", Domains: []string{"pathsso.test"}, Upstream: up}
	h.Options.AuthRules = []store.AuthRule{{Path: "/admin/", Mode: "oidc", OIDC: &store.OIDCAuth{ProviderID: pid, PassIdentity: true}}}
	mustCreateHost(t, st, h)

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(auth.Close)
	fa := &store.Host{Type: "proxy", Domains: []string{"fwd.test"}, Upstream: up}
	fa.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL, ResponseHeaders: []string{"X-Auth-User"}}
	mustCreateHost(t, st, fa)
	reload(t, e)

	forged := map[string]string{"Remote_User": "forged@example.com", "REMOTE_EMAIL": "forged@example.com", "remote_groups": "admins"}
	if rr := req(e, "GET", "pathsso.test", "/public/profile", "203.0.113.9", forged); rr.Code != http.StatusOK {
		t.Fatalf("public path: got %d", rr.Code)
	}
	for k := range seen {
		if n := normalizeHeaderName(k); n == "remote-user" || n == "remote-email" || n == "remote-groups" {
			t.Fatalf("upstream received forged identity header %q=%q", k, seen.Get(k))
		}
	}

	if rr := req(e, "GET", "fwd.test", "/", "203.0.113.9", map[string]string{"X_Auth_User": "forged"}); rr.Code != http.StatusOK {
		t.Fatalf("forward-auth host: got %d", rr.Code)
	}
	for k := range seen {
		if normalizeHeaderName(k) == "x-auth-user" {
			t.Fatalf("upstream received forged forward-auth header %q=%q", k, seen.Get(k))
		}
	}
}

// One source address cannot fill a UDP listener's session table and lock
// every other client out: sessions are also capped per source IP.
func TestUDPSessionCapPerSourceIP(t *testing.T) {
	oldMax, oldPerIP := udpMaxSessions, udpMaxSessionsPerIP
	udpMaxSessions, udpMaxSessionsPerIP = 3, 2
	t.Cleanup(func() { udpMaxSessions, udpMaxSessionsPerIP = oldMax, oldPerIP })

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], addr)
		}
	}()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	e, _ := newTestEngine(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "udp", ForwardHost: "127.0.0.1",
		ForwardPort: echo.LocalAddr().(*net.UDPAddr).Port, Enabled: true})

	roundTrip := func(src string) bool {
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(src)}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err != nil {
			t.Skipf("cannot send from %s on this system: %v", src, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
		if _, err := c.Write([]byte("ping")); err != nil {
			return false
		}
		buf := make([]byte, 4)
		n, err := c.Read(buf)
		return err == nil && string(buf[:n]) == "ping"
	}
	if !roundTrip("127.0.0.1") || !roundTrip("127.0.0.1") {
		t.Fatal("the first two sessions from one address should be served")
	}
	if roundTrip("127.0.0.1") {
		t.Fatal("a third session from the same address was served past its per-address cap")
	}
	if !roundTrip("127.0.0.2") {
		t.Fatal("a client from another address was locked out by the first address's sessions")
	}
}

// The public listeners close idle keep-alive connections instead of holding
// them open forever.
func TestPublicServerClosesIdleConnections(t *testing.T) {
	old := publicIdleTimeout
	publicIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { publicIdleTimeout = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newPublicServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }), nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the server sent data on an idle connection")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("an idle keep-alive connection stayed open for %v", elapsed)
	}
}

// Requests to an identity provider reuse one HTTP client per verification
// setting. Building a new transport per call leaked its idle connections on
// every login when certificate verification was skipped.
func TestIdPClientIsReused(t *testing.T) {
	for _, skip := range []bool{false, true} {
		p := store.OIDCProvider{SkipTLSVerify: skip}
		a, _ := idpContext(context.Background(), p).Value(oauth2.HTTPClient).(*http.Client)
		b, _ := idpContext(context.Background(), p).Value(oauth2.HTTPClient).(*http.Client)
		if a == nil || a != b {
			t.Fatalf("skipTlsVerify=%v: got clients %p and %p, want one shared client", skip, a, b)
		}
		if a.Timeout <= 0 {
			t.Fatalf("skipTlsVerify=%v: the IdP client has no timeout", skip)
		}
	}
}
