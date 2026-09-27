package engine

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"quicgate/internal/store"
)

// Data-plane hardening: one proxy for the default backends and every custom
// location (L-13), the client's scheme carried through from a trusted proxy
// (L-14), a Secure affinity cookie over TLS (I-6), the force-SSL redirect on a
// non-standard port (F-7), static hosts that serve files only (L-19), the
// default site compiled at reload (L-20), hop-by-hop headers kept out of a
// relayed forward-auth refusal (I-11), passive failover (F-12) and health
// probes that verify certificates (L-22).

// trustLoopback makes 127.0.0.1 a trusted proxy that reports the client in
// X-Forwarded-For, and returns a handler that applies it like Run does.
func trustLoopback(t *testing.T, e *Engine, st *store.Store) http.Handler {
	t.Helper()
	for k, v := range map[string]string{"trusted_proxies": "127.0.0.1", "real_ip_header": "X-Forwarded-For"} {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	reload(t, e)
	return e.wrapRealIP(http.HandlerFunc(e.serveHTTPS))
}

// send drives one request through h with the given peer address and headers.
func send(h http.Handler, host, path, peer string, tlsConn bool, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = peer + ":4000"
	if tlsConn {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// A custom location is the host with another backend: the host's header
// rules, X-Robots-Tag and Host override apply to it as to the default proxy.
func TestLocationGetsTheHostRules(t *testing.T) {
	var mu sync.Mutex
	seenHost, seenEdge := "", ""
	loc := backend(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHost, seenEdge = r.Host, r.Header.Get("X-Edge")
		mu.Unlock()
		_, _ = w.Write([]byte("loc"))
	})
	def := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("default")) })
	e, st := newTestEngine(t)
	h := &store.Host{Type: "proxy", Domains: []string{"loc.test"}, Upstream: def, Locations: []store.Location{{Path: "/api", Upstream: loc}}}
	h.Options.ResponseHeaders = []store.HeaderRule{{Op: "set", Name: "X-Frame-Options", Value: "DENY"}}
	h.Options.RequestHeaders = []store.HeaderRule{{Op: "set", Name: "X-Edge", Value: "{scheme}"}}
	h.Options.BlockIndexing = true
	h.Options.HostOverride = "internal.example"
	mustCreateHost(t, st, h)
	reload(t, e)

	rr := req(e, "GET", "loc.test", "/api/thing", "127.0.0.1", nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "loc" {
		t.Fatalf("location answered %d %q, want 200 loc", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("response header rule on a location path: X-Frame-Options=%q, want DENY", got)
	}
	if rr.Header().Get("X-Robots-Tag") == "" {
		t.Fatal("X-Robots-Tag missing on a location path")
	}
	mu.Lock()
	defer mu.Unlock()
	if seenHost != "internal.example" {
		t.Fatalf("location upstream saw Host %q, want the host override", seenHost)
	}
	if seenEdge != "http" {
		t.Fatalf("location upstream saw X-Edge %q, want the {scheme} placeholder expanded to http", seenEdge)
	}
}

// Behind a trusted proxy that terminated TLS, the upstream and the {scheme}
// placeholder see https; the header is not believed from anybody else, and a
// TLS request is never reported as plain.
func TestForwardedProtoFollowsTheTrustedProxy(t *testing.T) {
	var mu sync.Mutex
	var protos, schemes []string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Header.Get("X-Forwarded-Proto"))
		schemes = append(schemes, r.Header.Get("X-Scheme"))
		mu.Unlock()
	})
	e, st := newTestEngine(t)
	h := &store.Host{Type: "proxy", Domains: []string{"xfp.test"}, Upstream: up}
	h.Options.RequestHeaders = []store.HeaderRule{{Op: "set", Name: "X-Scheme", Value: "{scheme}"}}
	mustCreateHost(t, st, h)
	handler := trustLoopback(t, e, st)

	send(handler, "xfp.test", "/", "127.0.0.1", false, map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
	send(handler, "xfp.test", "/", "198.51.100.7", false, map[string]string{"X-Forwarded-Proto": "https"})
	send(handler, "xfp.test", "/", "127.0.0.1", true, map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "http"})
	send(handler, "xfp.test", "/", "198.51.100.7", false, nil)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"https", "http", "https", "http"}
	for i, w := range want {
		if protos[i] != w {
			t.Errorf("request %d: upstream saw X-Forwarded-Proto %q, want %q", i, protos[i], w)
		}
		if schemes[i] != w {
			t.Errorf("request %d: {scheme} expanded to %q, want %q", i, schemes[i], w)
		}
	}
}

// The forward-auth subrequest reports the client's scheme by the same rule.
func TestForwardAuthSeesTheClientScheme(t *testing.T) {
	var mu sync.Mutex
	var protos []string
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Header.Get("X-Forwarded-Proto"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(auth.Close)
	e, st := newTestEngine(t)
	h := &store.Host{Type: "proxy", Domains: []string{"fa.test"}, Upstream: backend(t, func(w http.ResponseWriter, r *http.Request) {})}
	h.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL}
	mustCreateHost(t, st, h)
	handler := trustLoopback(t, e, st)

	send(handler, "fa.test", "/", "127.0.0.1", false, map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
	send(handler, "fa.test", "/", "198.51.100.7", false, map[string]string{"X-Forwarded-Proto": "https"})
	mu.Lock()
	defer mu.Unlock()
	if len(protos) != 2 || protos[0] != "https" || protos[1] != "http" {
		t.Fatalf("auth server saw X-Forwarded-Proto %v, want [https http]", protos)
	}
}

// A refusal relayed from the auth server keeps its own headers (the challenge,
// the login redirect) but not those about the auth server's connection.
func TestForwardAuthRelayDropsHopByHopHeaders(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Basic realm=x")
		w.Header().Set("Location", "https://login.example/")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Connection", "X-Hop")
		w.Header().Set("X-Hop", "1")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(auth.Close)
	e, st := newTestEngine(t)
	h := &store.Host{Type: "proxy", Domains: []string{"fa.test"}, Upstream: backend(t, func(w http.ResponseWriter, r *http.Request) {})}
	h.Options.ForwardAuth = &store.ForwardAuth{URL: auth.URL}
	mustCreateHost(t, st, h)
	reload(t, e)

	rr := req(e, "GET", "fa.test", "/", "127.0.0.1", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" || rr.Header().Get("Location") == "" {
		t.Fatalf("end-to-end headers were not relayed: %v", rr.Header())
	}
	for _, name := range []string{"Keep-Alive", "Connection", "X-Hop"} {
		if v := rr.Header().Get(name); v != "" {
			t.Errorf("hop-by-hop header %s=%q was relayed", name, v)
		}
	}
}

// The affinity cookie is Secure when the client's connection is encrypted, and
// plain when it is not (a certMode none host could not read it back otherwise).
func TestStickyCookieIsSecureOverTLS(t *testing.T) {
	e, st := newTestEngine(t)
	a := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("A")) })
	b := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("B")) })
	h := &store.Host{Type: "proxy", Domains: []string{"s.test"}, Upstream: a, Upstreams: []store.Upstream{b}}
	h.Options.StickySessions = true
	mustCreateHost(t, st, h)
	reload(t, e)

	plain := send(http.HandlerFunc(e.serveHTTPS), "s.test", "/", "127.0.0.1", false, nil).Result().Cookies()
	if len(plain) == 0 || plain[0].Secure {
		t.Fatalf("plain request: cookies %v, want an affinity cookie without Secure", plain)
	}
	encrypted := send(http.HandlerFunc(e.serveHTTPS), "s.test", "/", "127.0.0.1", true, nil).Result().Cookies()
	if len(encrypted) == 0 || !encrypted[0].Secure {
		t.Fatalf("TLS request: cookies %v, want a Secure affinity cookie", encrypted)
	}
}

// The force-SSL redirect names the HTTPS port when it is not 443.
func TestForceSSLRedirectKeepsANonStandardPort(t *testing.T) {
	e, st := newTestEngine(t)
	e.cfg.HTTPSAddr = ":8443"
	if err := st.CreateHost(&store.Host{Type: "proxy", Domains: []string{"r.test"}, CertMode: "auto", ForceSSL: true, Enabled: true,
		Upstream: backend(t, func(w http.ResponseWriter, r *http.Request) {})}); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	redirect := func(host string) string {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/a?b=1", nil)
		r.Host = host
		rr := httptest.NewRecorder()
		e.serveHTTP(rr, r)
		if rr.Code != http.StatusMovedPermanently {
			t.Fatalf("status %d, want 301", rr.Code)
		}
		return rr.Header().Get("Location")
	}
	if got := redirect("r.test:80"); got != "https://r.test:8443/a?b=1" {
		t.Fatalf("Location %q, want https://r.test:8443/a?b=1", got)
	}
	e.cfg.HTTPSAddr = ":443"
	if got := redirect("r.test"); got != "https://r.test/a?b=1" {
		t.Fatalf("Location %q on the default port, want https://r.test/a?b=1", got)
	}
}

// A static host serves files: no directory listings, no dot-prefixed names
// except under /.well-known/.
func TestStaticHostServesFilesOnly(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "home")
	write("app/index.html", "app")
	write("app/.hidden", "hidden")
	write("docs/readme.txt", "readme")
	write(".env", "SECRET=1")
	write(".git/config", "[core]")
	write(".well-known/acme-challenge/token", "proof")

	e, st := newTestEngine(t)
	mustCreateHost(t, st, &store.Host{Type: "static", Domains: []string{"static.test"}, StaticRoot: root})
	reload(t, e)

	cases := []struct {
		path string
		code int
		body string
	}{
		{"/", http.StatusOK, "home"},
		{"/app/", http.StatusOK, "app"},
		{"/docs/readme.txt", http.StatusOK, "readme"},
		{"/.well-known/acme-challenge/token", http.StatusOK, "proof"},
		{"/docs/", http.StatusNotFound, ""},
		{"/docs", http.StatusNotFound, ""},
		{"/.env", http.StatusNotFound, ""},
		{"/.git/config", http.StatusNotFound, ""},
		{"/app/.hidden", http.StatusNotFound, ""},
		{"/.well-known/.hidden", http.StatusNotFound, ""},
	}
	for _, c := range cases {
		rr := req(e, "GET", "static.test", c.path, "127.0.0.1", nil)
		if rr.Code != c.code {
			t.Errorf("GET %s: %d, want %d (body %q)", c.path, rr.Code, c.code, rr.Body.String())
			continue
		}
		if c.body != "" && rr.Body.String() != c.body {
			t.Errorf("GET %s: body %q, want %q", c.path, rr.Body.String(), c.body)
		}
	}
}

// The default site is compiled at reload: an unknown host costs no database
// read, and a changed setting takes effect with the reload that follows it.
func TestDefaultSiteIsCompiledAtReload(t *testing.T) {
	e, st := newTestEngine(t)
	set := func(mode, value string) {
		t.Helper()
		if err := st.SetSetting("default_site", mode); err != nil {
			t.Fatal(err)
		}
		if err := st.SetSetting("default_site_value", value); err != nil {
			t.Fatal(err)
		}
	}
	set("html", "<p>one</p>")
	reload(t, e)
	if rr := req(e, "GET", "nobody.test", "/", "127.0.0.1", nil); rr.Code != http.StatusOK || rr.Body.String() != "<p>one</p>" {
		t.Fatalf("unknown host got %d %q, want the custom page", rr.Code, rr.Body.String())
	}
	set("redirect", "https://example.com/")
	if rr := req(e, "GET", "nobody.test", "/", "127.0.0.1", nil); rr.Code != http.StatusOK {
		t.Fatalf("a setting not yet reloaded changed the answer to %d", rr.Code)
	}
	reload(t, e)
	rr := req(e, "GET", "nobody.test", "/", "127.0.0.1", nil)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://example.com/" {
		t.Fatalf("after reload: %d %q, want a redirect to https://example.com/", rr.Code, rr.Header().Get("Location"))
	}
}

// A pool member that cannot be connected to is marked down by the request
// that found out, so the requests after it go to the other member instead of
// every other one failing until the periodic probe notices.
func TestUnreachableBackendIsAvoidedAtOnce(t *testing.T) {
	e, st := newTestEngine(t)
	alive := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("A")) })
	dead := store.Upstream{Scheme: "http", Host: "127.0.0.1", Port: freeTCPPort(t)}
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"pool.test"}, Upstream: alive, Upstreams: []store.Upstream{dead}})
	reload(t, e)

	var codes []int
	for i := 0; i < 8; i++ {
		codes = append(codes, req(e, "GET", "pool.test", "/", "127.0.0.1", nil).Code)
	}
	failures := 0
	for _, c := range codes {
		if c == http.StatusBadGateway {
			failures++
		}
	}
	if failures > 1 {
		t.Fatalf("responses %v: the unreachable member was tried again after its first failure", codes)
	}
	if failures == 0 {
		t.Fatalf("responses %v: test setup, the unreachable member was never tried", codes)
	}
	for _, s := range e.HealthStatuses() {
		if s.Target == upstreamKey(dead) && (s.Up || s.LastErr == "") {
			t.Fatalf("health status of the unreachable member: %+v, want down with the error", s)
		}
	}
	// The probe brings a member back once it answers.
	up, errStr := e.health.probe("http", hostPort(alive.Host, alive.Port), 0, probeClient(false, ""))
	if !up || errStr != "" {
		t.Fatalf("probe of a live backend: up=%v err=%q", up, errStr)
	}
}

// The probe verifies a backend's certificate unless the host skips
// verification for its own traffic; backends that do not speak HTTPS are
// judged as before.
func TestHealthProbeVerifiesCertificates(t *testing.T) {
	h := &healthChecker{targets: map[string]*targetHealth{}}
	selfSigned := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(selfSigned.Close)
	u, _ := url.Parse(selfSigned.URL)
	if up, errStr := h.probe("https", u.Host, 0, probeClient(false, "")); up || errStr == "" {
		t.Fatalf("a backend with a certificate nobody vouches for was probed up=%v err=%q", up, errStr)
	}
	if up, errStr := h.probe("https", u.Host, 0, probeClient(true, "")); !up {
		t.Fatalf("with verification skipped: up=%v err=%q", up, errStr)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	t.Cleanup(plain.Close)
	pu, _ := url.Parse(plain.URL)
	if up, _ := h.probe("http", pu.Host, 0, probeClient(false, "")); !up {
		t.Fatal("a plain HTTP backend answering 418 was probed down")
	}
	if up, _ := h.probe("http", hostPort("127.0.0.1", echoBackend(t)), 0, probeClient(false, "")); !up {
		t.Fatal("a non-HTTP backend that accepts connections was probed down")
	}
}

// Reload hands the probe each host's own TLS settings for its backends.
func TestReloadRegistersProbeTLSSettings(t *testing.T) {
	e, st := newTestEngine(t)
	lax := store.Upstream{Scheme: "https", Host: "127.0.0.1", Port: 8443}
	strict := store.Upstream{Scheme: "https", Host: "127.0.0.1", Port: 8444}
	h := &store.Host{Type: "proxy", Domains: []string{"lax.test"}, Upstream: lax}
	h.Options.SkipTLSVerify, h.Options.UpstreamSNI = true, "backend.internal"
	mustCreateHost(t, st, h)
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"strict.test"}, Upstream: strict})
	reload(t, e)

	e.health.mu.RLock()
	defer e.health.mu.RUnlock()
	if t1 := e.health.targets[upstreamKey(lax)]; t1 == nil || !t1.tlsSkipVerify || t1.tlsServerName != "backend.internal" {
		t.Fatalf("lax host's backend registered as %+v, want verification skipped with SNI backend.internal", t1)
	}
	if t2 := e.health.targets[upstreamKey(strict)]; t2 == nil || t2.tlsSkipVerify || t2.tlsServerName != "" {
		t.Fatalf("strict host's backend registered as %+v, want verification on", t2)
	}
}
