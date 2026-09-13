package engine

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Q01 over HTTP/3: the QUIC listener shares serveHTTPS with the TLS listener,
// and quic-go exposes the handshake state (SNI and peer certificates) on each
// request, so the same per-request client-certificate check applies. This runs
// a real QUIC exchange on UDP loopback to prove it rather than assume it.
func TestMTLSHTTP3HostMustMatchSNI(t *testing.T) {
	f := newMTLSFixture(t, "require")

	cfg := f.e.tlsConfig()
	serverCert := f.serverCA.issue(t, "server", []string{"public.test", "secure.test"}, x509.ExtKeyUsageServerAuth)
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil }
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP loopback: %v", err)
	}
	srv := &http3.Server{Handler: http.HandlerFunc(f.e.serveHTTPS), TLSConfig: http3.ConfigureTLSConfig(cfg)}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })

	get := func(sni, host string, cert *tls.Certificate) (int, string, error) {
		roots := x509.NewCertPool()
		roots.AddCert(f.serverCA.cert)
		tc := &tls.Config{RootCAs: roots, ServerName: sni}
		if cert != nil {
			tc.Certificates = []tls.Certificate{*cert}
		}
		tr := &http3.Transport{TLSClientConfig: tc}
		defer tr.Close()
		c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		r, err := http.NewRequest(http.MethodGet, "https://"+pc.LocalAddr().String()+"/", nil)
		if err != nil {
			return 0, "", err
		}
		r.Host = host
		resp, err := c.Do(r)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.ProtoMajor != 3 {
			t.Fatalf("test setup: response came back over HTTP/%d, want HTTP/3", resp.ProtoMajor)
		}
		return resp.StatusCode, string(body), nil
	}

	// Control: with a valid certificate on the matching name, HTTP/3 works.
	if code, body, err := get("secure.test", "secure.test", &f.clientCert); err != nil || code != http.StatusOK || body != "backend:secure.test" {
		t.Fatalf("h3 secure.test with a certificate: code=%d body=%q err=%v, want 200", code, body, err)
	}
	// The bypass: public SNI, protected authority, no certificate.
	code, body, err := get("public.test", "secure.test", nil)
	if err != nil {
		t.Fatalf("h3 request: %v", err)
	}
	if code != http.StatusMisdirectedRequest || body == "backend:secure.test" {
		t.Fatalf("h3 public SNI + protected authority: code=%d body=%q, want 421", code, body)
	}
}
