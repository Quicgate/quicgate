package docker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quicgate/internal/store"
)

// testPKI writes a CA, a server certificate for 127.0.0.1 signed by it, and a
// client certificate signed by it, the way "dockerd --tlsverify" is set up.
type testPKI struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
	pool                                                 *x509.CertPool
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test docker CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP) (string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		return write(cn+".pem", &pem.Block{Type: "CERTIFICATE", Bytes: der}),
			write(cn+"-key.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	pki := testPKI{caFile: write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	pki.pool.AddCert(caCert)
	pki.serverCert, pki.serverKey = issue(2, "server", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	pki.clientCert, pki.clientKey = issue(3, "client", x509.ExtKeyUsageClientAuth, nil)
	return pki
}

// A remote daemon behind TLS with --tlsverify: quicgate verifies it against
// caFile and presents certFile/keyFile. Without the client certificate the
// daemon refuses; with a CA that did not sign the daemon, quicgate refuses.
func TestClientTLSVerifyModel(t *testing.T) {
	pki := newTestPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			_, _ = w.Write([]byte("OK"))
			return
		}
		http.NotFound(w, r)
	}))
	serverPair, err := tls.LoadX509KeyPair(pki.serverCert, pki.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientCAs: pki.pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "https://")
	ctx := context.Background()

	for _, connect := range []string{"https://" + hostport, "tcp://" + hostport} {
		ep := Endpoint{Name: "remote", Connect: connect, Address: "127.0.0.1", CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey}
		base, tr, err := transportFor(ep)
		if err != nil || base != "https://"+hostport || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil || len(tr.TLSClientConfig.Certificates) != 1 {
			t.Fatalf("%s: base=%s tls=%+v err=%v", connect, base, tr.TLSClientConfig, err)
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("verification switched off")
		}
		cli, err := NewClient(ep)
		if err != nil {
			t.Fatal(err)
		}
		if err := cli.Ping(ctx); err != nil {
			t.Fatalf("%s: ping over verified TLS with a client certificate: %v", connect, err)
		}
	}

	// No client certificate: the daemon's --tlsverify refuses the connection.
	noCert, err := NewClient(Endpoint{Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: pki.caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := noCert.Ping(ctx); err == nil {
		t.Fatal("the daemon accepted a connection without the client certificate")
	}

	// Plain tcp:// to a TLS daemon does not speak its language.
	plain, err := NewClient(Endpoint{Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Ping(ctx); err == nil {
		t.Fatal("a plaintext connection to a TLS daemon succeeded")
	}

	// A CA that did not sign the daemon: quicgate refuses to talk to it.
	other := newTestPKI(t)
	wrongCA, err := NewClient(Endpoint{Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: other.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongCA.Ping(ctx); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a daemon not signed by caFile was trusted: %v", err)
	}

	// Files that do not open or hold no CA are errors when the client is built.
	for name, ep := range map[string]Endpoint{
		"missing CA file":    {Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: filepath.Join(t.TempDir(), "nope.pem")},
		"CA file without CA": {Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: pki.clientKey},
		"key mismatch":       {Name: "r", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.serverKey},
	} {
		if _, err := NewClient(ep); err == nil {
			t.Errorf("%s: a client was built", name)
		}
	}

	// An endpoint whose files do not open is kept in the provider, shown with
	// its error, and never silently reduced to a plaintext connection.
	p := NewProvider(Options{Endpoints: []Endpoint{{Name: "broken", Connect: "tcp://" + hostport, Address: "127.0.0.1", CAFile: filepath.Join(t.TempDir(), "nope.pem")}}}, Hooks{
		Apply: func([]store.Host, []store.Stream) {}, ExistingDomains: func() map[string]bool { return nil },
	})
	if len(p.eps) != 1 || p.eps[0].cli != nil || !strings.Contains(p.eps[0].errMsg, "caFile") {
		t.Fatalf("broken endpoint state: cli=%v err=%q", p.eps[0].cli, p.eps[0].errMsg)
	}
	p.aggregate()
	if st := p.Status(); len(st.Endpoints) != 1 || st.Endpoints[0].Connected || !strings.Contains(st.Endpoints[0].Error, "caFile") {
		t.Fatalf("status of the broken endpoint = %+v", st.Endpoints)
	}
}
