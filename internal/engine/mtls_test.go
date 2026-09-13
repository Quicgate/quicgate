package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"quicgate/internal/store"
)

// Mutual TLS is negotiated in the handshake from the SNI, but requests are
// routed by Host. These tests drive real TLS connections (a throwaway CA, a
// verified server certificate) through the engine's own TLS config, so the
// SNI and the Host header can be made to disagree the way a client can.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// issue signs a leaf certificate for either server or client use.
func (ca *testCA) issue(t *testing.T, cn string, dnsNames []string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSEngine serves e.serveHTTPS over real TLS using the engine's own TLS
// configuration (including its per-SNI client-certificate policy), with a test
// server certificate standing in for certmagic's.
func startTLSEngine(t *testing.T, e *Engine, serverCert tls.Certificate) *httptest.Server {
	t.Helper()
	cfg := e.tlsConfig()
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(e.serveHTTPS))
	srv.TLS = cfg
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// tlsClient dials the test server presenting sni in the handshake, optionally
// with a client certificate. forceH2 pins the connection to HTTP/2.
func tlsClient(t *testing.T, serverCA *testCA, sni string, clientCert *tls.Certificate, forceH2 bool) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)
	tc := &tls.Config{RootCAs: roots, ServerName: sni}
	if clientCert != nil {
		tc.Certificates = []tls.Certificate{*clientCert}
	}
	if forceH2 {
		tc.NextProtos = []string{"h2"}
	}
	tr := &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// getAs sends GET / to srv with the given Host header and reports the status,
// the body and whether the request reused an existing connection.
func getAs(t *testing.T, c *http.Client, srv *httptest.Server, host string) (int, string, bool, error) {
	t.Helper()
	reused := false
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
	r, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	resp, err := c.Do(r)
	if err != nil {
		return 0, "", reused, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), reused, nil
}

// createHost stores a TLS host (mustCreateHost forces certMode none, which an
// mTLS host may not use).
func createTLSHost(t *testing.T, st *store.Store, h *store.Host) {
	t.Helper()
	h.CertMode, h.Enabled = "auto", true
	if err := st.CreateHost(h); err != nil {
		t.Fatalf("create host: %v", err)
	}
}

type mtlsFixture struct {
	e          *Engine
	st         *store.Store
	srv        *httptest.Server
	serverCA   *testCA
	clientCA   *testCA
	clientCert tls.Certificate
	secure     *store.Host
}

// newMTLSFixture wires public.test (no client certificates) and secure.test
// (client certificate required, issued by clientCA) behind one TLS listener.
func newMTLSFixture(t *testing.T, mode string) *mtlsFixture {
	t.Helper()
	e, st := newTestEngine(t)
	serverCA := newTestCA(t, "server-ca")
	clientCA := newTestCA(t, "client-ca")
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("backend:" + r.Host)) })

	createTLSHost(t, st, &store.Host{Type: "proxy", Domains: []string{"public.test"}, Upstream: up})
	secure := &store.Host{Type: "proxy", Domains: []string{"secure.test"}, Upstream: up}
	secure.Options.ClientCert = &store.ClientCert{Mode: mode, CAPEM: clientCA.pem}
	createTLSHost(t, st, secure)
	reload(t, e)

	serverCert := serverCA.issue(t, "server", []string{"public.test", "secure.test"}, x509.ExtKeyUsageServerAuth)
	return &mtlsFixture{
		e: e, st: st, srv: startTLSEngine(t, e, serverCert),
		serverCA: serverCA, clientCA: clientCA,
		clientCert: clientCA.issue(t, "client", nil, x509.ExtKeyUsageClientAuth),
		secure:     secure,
	}
}

// Control: the handshake policy itself works when SNI and Host agree.
func TestMTLSMatchingSNIEnforced(t *testing.T) {
	f := newMTLSFixture(t, "require")

	if _, _, _, err := getAs(t, tlsClient(t, f.serverCA, "secure.test", nil, false), f.srv, "secure.test"); err == nil {
		t.Fatal("secure.test without a client certificate completed a request, want a handshake failure")
	}
	code, body, _, err := getAs(t, tlsClient(t, f.serverCA, "secure.test", &f.clientCert, false), f.srv, "secure.test")
	if err != nil || code != http.StatusOK || body != "backend:secure.test" {
		t.Fatalf("secure.test with a valid certificate: code=%d body=%q err=%v, want 200 from the backend", code, body, err)
	}
}

// Q01: authenticating the handshake for a public name must not unlock a
// certificate-protected Host on the same connection.
func TestMTLSHostMustMatchSNI(t *testing.T) {
	f := newMTLSFixture(t, "require")

	code, body, _, err := getAs(t, tlsClient(t, f.serverCA, "public.test", nil, false), f.srv, "secure.test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if code != http.StatusMisdirectedRequest || body == "backend:secure.test" {
		t.Fatalf("public SNI + protected Host: code=%d body=%q, want 421 without reaching the backend", code, body)
	}
	// The reverse direction is refused too: a connection negotiated for the
	// protected name is not a channel to other hosts.
	code, _, _, err = getAs(t, tlsClient(t, f.serverCA, "secure.test", &f.clientCert, false), f.srv, "public.test")
	if err != nil || code != http.StatusMisdirectedRequest {
		t.Fatalf("protected SNI + public Host: code=%d err=%v, want 421", code, err)
	}
}

// Q01: HTTP/2 lets one connection carry several authorities. A connection
// opened for public.test must not be reused to reach secure.test.
func TestMTLSHTTP2ReuseForProtectedAuthority(t *testing.T) {
	f := newMTLSFixture(t, "require")
	c := tlsClient(t, f.serverCA, "public.test", nil, true)

	code, _, _, err := getAs(t, c, f.srv, "public.test")
	if err != nil || code != http.StatusOK {
		t.Fatalf("first request to public.test: code=%d err=%v", code, err)
	}
	code, body, reused, err := getAs(t, c, f.srv, "secure.test")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if !reused {
		t.Fatal("test setup: the second request did not reuse the HTTP/2 connection")
	}
	if code != http.StatusMisdirectedRequest || body == "backend:secure.test" {
		t.Fatalf("reused h2 connection for secure.test: code=%d body=%q, want 421", code, body)
	}
}

// Q01: the certificate is re-checked against the host's CURRENT policy on every
// request, so replacing the CA on reload also applies to live connections.
func TestMTLSPolicyChangeAppliesToOpenConnections(t *testing.T) {
	f := newMTLSFixture(t, "require")
	c := tlsClient(t, f.serverCA, "secure.test", &f.clientCert, false)

	if code, _, _, err := getAs(t, c, f.srv, "secure.test"); err != nil || code != http.StatusOK {
		t.Fatalf("before the CA change: code=%d err=%v", code, err)
	}
	otherCA := newTestCA(t, "replacement-ca")
	f.secure.Options.ClientCert.CAPEM = otherCA.pem
	if err := f.st.UpdateHost(f.secure); err != nil {
		t.Fatalf("update host: %v", err)
	}
	reload(t, f.e)

	code, body, reused, err := getAs(t, c, f.srv, "secure.test")
	if err != nil {
		t.Fatalf("after the CA change: %v", err)
	}
	if !reused {
		t.Fatal("test setup: the request after reload did not reuse the verified connection")
	}
	if code != http.StatusForbidden || body == "backend:secure.test" {
		t.Fatalf("certificate from a CA the host no longer trusts: code=%d body=%q, want 403", code, body)
	}
}

// Q01: optional mode lets clients without a certificate through, but a
// presented certificate must still verify against the requested host's CA.
func TestMTLSRequestModeVerifiesPresentedCertificate(t *testing.T) {
	f := newMTLSFixture(t, "request")

	if code, _, _, err := getAs(t, tlsClient(t, f.serverCA, "secure.test", nil, false), f.srv, "secure.test"); err != nil || code != http.StatusOK {
		t.Fatalf("request mode without a certificate: code=%d err=%v, want 200", code, err)
	}
	c := tlsClient(t, f.serverCA, "secure.test", &f.clientCert, false)
	if code, _, _, err := getAs(t, c, f.srv, "secure.test"); err != nil || code != http.StatusOK {
		t.Fatalf("request mode with a trusted certificate: code=%d err=%v, want 200", code, err)
	}
	// A new connection with an untrusted certificate already fails the
	// handshake; a connection verified before the CA was replaced must be
	// refused by the per-request check.
	f.secure.Options.ClientCert.CAPEM = newTestCA(t, "replacement").pem
	if err := f.st.UpdateHost(f.secure); err != nil {
		t.Fatalf("update host: %v", err)
	}
	reload(t, f.e)
	code, _, reused, err := getAs(t, c, f.srv, "secure.test")
	if err != nil {
		t.Fatalf("after the CA change: %v", err)
	}
	if !reused {
		t.Fatal("test setup: the request after reload did not reuse the verified connection")
	}
	if code != http.StatusForbidden {
		t.Fatalf("request mode, presented certificate no longer trusted: code=%d, want 403", code)
	}
}

// Q01: a host that needs client certificates is never served over plain HTTP,
// whatever its force-SSL flag says.
func TestMTLSHostNeverServedOverPlainHTTP(t *testing.T) {
	f := newMTLSFixture(t, "require")
	if f.secure.ForceSSL {
		t.Fatal("test setup: secure.test must not have forceSsl")
	}
	r := httptest.NewRequest(http.MethodGet, "http://secure.test/data", nil)
	r.Host = "secure.test"
	r.RemoteAddr = "203.0.113.9:50000"
	rr := httptest.NewRecorder()
	f.e.serveHTTP(rr, r)
	if rr.Body.String() == "backend:secure.test" {
		t.Fatal("plain HTTP reached the backend of a client-certificate host")
	}
	if rr.Code != http.StatusMovedPermanently || rr.Header().Get("Location") != "https://secure.test/data" {
		t.Fatalf("plain HTTP: code=%d location=%q, want a 301 to https", rr.Code, rr.Header().Get("Location"))
	}
}

// Q01: a CA bundle that does not parse is rejected when saved, and a broken
// bundle already in the running config closes the host instead of silently
// dropping the client-certificate requirement.
func TestMTLSInvalidCABundle(t *testing.T) {
	_, st := newTestEngine(t)
	up := store.Upstream{Scheme: "http", Host: "127.0.0.1", Port: 9}
	for _, bundle := range []string{"", "not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		h := &store.Host{Type: "proxy", Domains: []string{"badca.test"}, Upstream: up, CertMode: "auto", Enabled: true}
		h.Options.ClientCert = &store.ClientCert{Mode: "require", CAPEM: bundle}
		if err := st.CreateHost(h); err == nil {
			t.Fatalf("CA bundle %q was accepted, want a validation error", bundle)
		}
	}
	h := &store.Host{Type: "proxy", Domains: []string{"nocertmode.test"}, Upstream: up, CertMode: "none", Enabled: true}
	h.Options.ClientCert = &store.ClientCert{Mode: "require", CAPEM: newTestCA(t, "ca").pem}
	if err := st.CreateHost(h); err == nil {
		t.Fatal("client certificates on a certMode=none host were accepted, want a validation error")
	}

	// A broken row that is already live (injected past validation).
	e, _ := newTestEngine(t)
	serverCA := newTestCA(t, "server-ca")
	upOK := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("backend")) })
	broken := store.Host{Type: "proxy", Domains: []string{"broken.test"}, Upstream: upOK, CertMode: "auto", Enabled: true}
	broken.Options.ClientCert = &store.ClientCert{Mode: "require", CAPEM: "garbage"}
	e.SetDockerRoutes([]store.Host{broken}, nil)
	srv := startTLSEngine(t, e, serverCA.issue(t, "server", []string{"broken.test"}, x509.ExtKeyUsageServerAuth))

	code, body, _, err := getAs(t, tlsClient(t, serverCA, "broken.test", nil, false), srv, "broken.test")
	if err == nil && (code == http.StatusOK || body == "backend") {
		t.Fatalf("host with an unparsable CA bundle served the backend: code=%d body=%q", code, body)
	}
}
