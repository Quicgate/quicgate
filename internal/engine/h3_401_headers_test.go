package engine

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"quicgate/internal/store"
)

// TestUpstream401HeadersOverEveryProtocol pins that a backend's 401 reaches
// the client with its own headers over HTTP/1.1, HTTP/2 and HTTP/3 alike, and
// that the client's Authorization reaches the backend on all three.
//
// It came out of a 2026-11 report that h3 "lost" KasmVNC's WWW-Authenticate:
// browsers saw a bare 401 with only quicgate's headers and no login box. The
// cause was KasmVNC, not quicgate: it counts every 401 it sends to a request
// without credentials as a failed login, and after five from one address
// (taken from X-Forwarded-For) it answers "HTTP/1.1 401 Forbidden" with no
// headers at all. One page load (/, favicon.ico, apple-touch-icon.png) is
// enough to trip it, on any protocol. This test keeps the proxy side proven so
// the next bare 401 is looked for upstream first.
//
// The backend is a raw TCP server answering the way KasmVNC does: no body,
// Connection: close, no Content-Length. The host carries the options the Kasm
// host had (compression, X-Robots-Tag, exploit and bot filters), because those
// all touch the response on its way out.
func TestUpstream401HeadersOverEveryProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var gotAuth []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				auth := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
					if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, "Authorization") {
						auth = strings.TrimSpace(v)
					}
				}
				mu.Lock()
				gotAuth = append(gotAuth, auth)
				mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 401 Unauthorized\r\n"+
					"Connection: close\r\n"+
					"WWW-Authenticate: Basic realm=\"Websockify\"\r\n"+
					"Cross-Origin-Embedder-Policy: require-corp\r\n"+
					"Cross-Origin-Opener-Policy: same-origin\r\n\r\n")
			}(c)
		}
	}()

	e, st := newTestEngine(t)
	if err := st.CreateHost(&store.Host{
		Type: "proxy", Domains: []string{"kasm.test"}, CertMode: "none", Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port},
		Options:  store.Options{Compression: true, BlockIndexing: true, BlockExploits: true, BlockBadBots: true},
	}); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	ca := newTestCA(t, "server-ca")
	cert := ca.issue(t, "server", []string{"kasm.test"}, x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	clientTLS := func(alpn ...string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: "kasm.test", NextProtos: alpn}
	}

	tcpSrv := startTLSEngine(t, e, cert)

	cfg := e.tlsConfig()
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP loopback: %v", err)
	}
	h3srv := &http3.Server{Handler: http.HandlerFunc(e.serveHTTPS), TLSConfig: http3.ConfigureTLSConfig(cfg)}
	go func() { _ = h3srv.Serve(pc) }()
	t.Cleanup(func() { _ = h3srv.Close(); _ = pc.Close() })

	h1 := &http.Transport{TLSClientConfig: clientTLS("http/1.1")}
	h2 := &http.Transport{TLSClientConfig: clientTLS("h2"), ForceAttemptHTTP2: true}
	h3 := &http3.Transport{TLSClientConfig: clientTLS()}
	t.Cleanup(func() { h1.CloseIdleConnections(); h2.CloseIdleConnections(); _ = h3.Close() })

	cases := []struct {
		name  string
		base  string
		rt    http.RoundTripper
		major int
	}{
		{"HTTP/1.1", tcpSrv.URL, h1, 1},
		{"HTTP/2", tcpSrv.URL, h2, 2},
		{"HTTP/3", "https://" + pc.LocalAddr().String(), h3, 3},
	}
	for _, c := range cases {
		for _, auth := range []string{"", "Basic dXNlcjpwYXNz"} {
			name := c.name + " no credentials"
			if auth != "" {
				name = c.name + " with credentials"
			}
			t.Run(name, func(t *testing.T) {
				mu.Lock()
				before := len(gotAuth)
				mu.Unlock()

				r, err := http.NewRequest(http.MethodGet, c.base+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Host = "kasm.test"
				// A browser's shape: bad-bot filtering refuses Go's own agent.
				r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0.0.0 Safari/537.36")
				r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				if auth != "" {
					r.Header.Set("Authorization", auth)
				}
				resp, err := (&http.Client{Transport: c.rt, Timeout: 10 * time.Second}).Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if resp.ProtoMajor != c.major {
					t.Fatalf("test setup: answered over HTTP/%d, want HTTP/%d", resp.ProtoMajor, c.major)
				}
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want the backend's 401", resp.StatusCode)
				}
				for k, want := range map[string]string{
					"WWW-Authenticate":             `Basic realm="Websockify"`,
					"Cross-Origin-Embedder-Policy": "require-corp",
					"Cross-Origin-Opener-Policy":   "same-origin",
					"X-Robots-Tag":                 "noindex, nofollow, nosnippet, noarchive",
				} {
					if got := resp.Header.Get(k); got != want {
						t.Errorf("%s = %q, want %q", k, got, want)
					}
				}

				mu.Lock()
				defer mu.Unlock()
				if len(gotAuth) != before+1 {
					t.Fatalf("backend saw %d requests, want 1", len(gotAuth)-before)
				}
				if got := gotAuth[before]; got != auth {
					t.Errorf("backend got Authorization %q, want %q", got, auth)
				}
			})
		}
	}
}
