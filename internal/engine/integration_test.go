package engine

// End-to-end feature tests. Each boots a real engine over a temp SQLite store,
// registers fake upstreams, seeds config through the real store + Reload, then
// drives requests through the full HTTPS pipeline (routing -> access list ->
// middleware -> reverse proxy) with an explicit client IP and Host. Runs under
// `go test`, no network fixtures or Docker. Add a feature test by copying one
// of these: seed a host/access-list/stream, reload, assert on req().

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"quicgate/internal/store"
)

func newTestEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(Config{DisableTLS: true, DataDir: dir}, st), st
}

// backend starts a fake upstream and returns its Upstream descriptor.
func backend(t *testing.T, h http.HandlerFunc) store.Upstream {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	port, _ := strconv.Atoi(u.Port())
	return store.Upstream{Scheme: "http", Host: u.Hostname(), Port: port}
}

func reload(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

// req drives one request through the full routing/access/proxy pipeline.
func req(e *Engine, method, host, path, clientIP string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = clientIP + ":50000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	e.serveHTTPS(rr, r)
	return rr
}

func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func mustCreateHost(t *testing.T, st *store.Store, h *store.Host) {
	t.Helper()
	h.CertMode, h.Enabled = "none", true
	if err := st.CreateHost(h); err != nil {
		t.Fatalf("create host: %v", err)
	}
}

func mustCreateACL(t *testing.T, st *store.Store, a *store.AccessList) int64 {
	t.Helper()
	if err := st.CreateAccessList(a); err != nil {
		t.Fatalf("create access list: %v", err)
	}
	return a.ID
}

// --- load balancing ---

func TestRoundRobinLoadBalancing(t *testing.T) {
	e, st := newTestEngine(t)
	a := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("A")) })
	b := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("B")) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"lb.test"}, Upstream: a, Upstreams: []store.Upstream{b}})
	reload(t, e)

	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		rr := req(e, "GET", "lb.test", "/", "127.0.0.1", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, rr.Code)
		}
		seen[rr.Body.String()]++
	}
	if seen["A"] == 0 || seen["B"] == 0 {
		t.Fatalf("expected both backends hit across 10 requests, got %v", seen)
	}
}

// --- IP access lists ---

func TestIPAccessList(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"gated.test"}, Upstream: up, AccessListID: &id})
	reload(t, e)

	if rr := req(e, "GET", "gated.test", "/", "10.1.2.3", nil); rr.Code != http.StatusOK {
		t.Fatalf("allowed IP: got %d, want 200", rr.Code)
	}
	if rr := req(e, "GET", "gated.test", "/", "203.0.113.9", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("blocked IP: got %d, want 403", rr.Code)
	}
}

// --- method-scoped rules + basic auth + satisfy=any ---

func TestMethodScopedRulesWithAuth(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "rw", Satisfy: "any",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "0.0.0.0/0", Methods: []string{"GET", "HEAD"}}},
		Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"rw.test"}, Upstream: up, AccessListID: &id})
	reload(t, e)

	if rr := req(e, "GET", "rw.test", "/", "203.0.113.9", nil); rr.Code != http.StatusOK {
		t.Fatalf("public GET: got %d, want 200", rr.Code)
	}
	if rr := req(e, "POST", "rw.test", "/", "203.0.113.9", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST without auth: got %d, want 401", rr.Code)
	}
	if rr := req(e, "POST", "rw.test", "/", "203.0.113.9", map[string]string{"Authorization": basic("u", "p")}); rr.Code != http.StatusOK {
		t.Fatalf("POST with auth: got %d, want 200", rr.Code)
	}
}

// --- CORS preflight bypass ---

func TestCORSPreflightEndToEnd(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "auth", Satisfy: "all",
		Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"cors.test"}, Upstream: up, AccessListID: &id})
	reload(t, e)

	// real request without creds is blocked
	if rr := req(e, "POST", "cors.test", "/", "203.0.113.9", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed POST: got %d, want 401", rr.Code)
	}
	// preflight passes through to the backend
	rr := req(e, "OPTIONS", "cors.test", "/", "203.0.113.9", map[string]string{"Access-Control-Request-Method": "POST"})
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("preflight should bypass the gate, got %d", rr.Code)
	}
}

// --- redirection hosts ---

func TestRedirectHost(t *testing.T) {
	e, st := newTestEngine(t)
	mustCreateHost(t, st, &store.Host{Type: "redirect", Domains: []string{"old.test"},
		Redirect: &store.Redirect{HTTPCode: 308, TargetScheme: "https", TargetHost: "new.test", PreservePath: true}})
	reload(t, e)

	rr := req(e, "GET", "old.test", "/path?x=1", "127.0.0.1", nil)
	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("redirect status: got %d, want 308", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://new.test/path?x=1" {
		t.Fatalf("redirect location: got %q", loc)
	}
}

// --- path rewrite ---

func TestPathRewriteStripPrefix(t *testing.T) {
	e, st := newTestEngine(t)
	var got string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path; w.WriteHeader(http.StatusOK) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"rw2.test"}, Upstream: up,
		Options: store.Options{PathRewrite: &store.PathRewrite{StripPrefix: "/api"}}})
	reload(t, e)

	if rr := req(e, "GET", "rw2.test", "/api/items", "127.0.0.1", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if got != "/items" {
		t.Fatalf("backend saw path %q, want /items", got)
	}
}

// --- request header injection ---

func TestRequestHeaderRule(t *testing.T) {
	e, st := newTestEngine(t)
	var seen string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("X-Injected"); w.WriteHeader(http.StatusOK) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"hdr.test"}, Upstream: up,
		Options: store.Options{RequestHeaders: []store.HeaderRule{{Op: "set", Name: "X-Injected", Value: "yes"}}}})
	reload(t, e)

	req(e, "GET", "hdr.test", "/", "127.0.0.1", nil)
	if seen != "yes" {
		t.Fatalf("backend saw X-Injected=%q, want yes", seen)
	}
}

// --- block common exploits ---

func TestBlockExploits(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"sec.test"}, Upstream: up,
		Options: store.Options{BlockExploits: true}})
	reload(t, e)

	if rr := req(e, "GET", "sec.test", "/ok", "127.0.0.1", nil); rr.Code != http.StatusOK {
		t.Fatalf("clean request: got %d, want 200", rr.Code)
	}
	if rr := req(e, "GET", "sec.test", "/x?file=/etc/passwd", "127.0.0.1", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("exploit request: got %d, want 403", rr.Code)
	}
}

// --- per-IP rate limiting ---

func TestRateLimit(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"rl.test"}, Upstream: up,
		Options: store.Options{RateLimit: &store.RateLimit{RPS: 1, Burst: 1}}})
	reload(t, e)

	if rr := req(e, "GET", "rl.test", "/", "198.51.100.7", nil); rr.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rr.Code)
	}
	if rr := req(e, "GET", "rl.test", "/", "198.51.100.7", nil); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("burst-exceeding request: got %d, want 429", rr.Code)
	}
}

// --- L4 TCP stream forwarding + source filtering ---

func TestTCPStreamForward(t *testing.T) {
	// echo backend
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	backendPort := echo.Addr().(*net.TCPAddr).Port

	// claim then release a free port for the stream to listen on
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	listenPort := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	sm := NewStreamManager()
	t.Cleanup(sm.StopAll)
	sm.Sync([]store.Stream{{ListenPort: listenPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: backendPort, Enabled: true}}, nil, nil)

	var conn net.Conn
	for i := 0; i < 50; i++ { // give the listener a moment to bind
		conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo returned %q, want ping", buf)
	}
}
