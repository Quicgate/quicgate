package engine

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"quicgate/internal/store"
)

// A replaced or restored custom certificate is what the TLS listener serves
// after the reload. The certificate cache used to keep every certificate it
// had loaded, so the old one could go on being served for the same name.
func TestCustomCertificateReplacedAndRestoredIsServed(t *testing.T) {
	e, st := newTestEngine(t)
	if err := st.CreateUser("admin@example.com", "hash", false); err != nil {
		t.Fatal(err)
	}
	a, err := st.GenerateSelfSigned("A", []string{"certswap.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	if err := st.CreateHost(&store.Host{Type: "proxy", Domains: []string{"certswap.test"}, Upstream: up,
		CertMode: "custom", CertID: &a.ID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	e.cfg.DisableTLS = false
	reload(t, e)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(e.serveHTTPS))
	srv.TLS = e.tlsConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	served := func() string {
		t.Helper()
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "certswap.test", InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	serialOf := func(id int64) string {
		t.Helper()
		certPEM, _, err := st.GetCustomCertPEM(id)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(certPEM))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert.SerialNumber.String()
	}
	serialA := serialOf(a.ID)
	if got := served(); got != serialA {
		t.Fatalf("initial certificate: served %s, want A %s", got, serialA)
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := st.Snapshot(snap); err != nil {
		t.Fatal(err)
	}

	// Replace A's PEM in place with a new certificate B.
	b, err := st.GenerateSelfSigned("B", []string{"certswap.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	certB, keyB, err := st.GetCustomCertPEM(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCustomCertPEM(a.ID, &store.CustomCert{Name: "A", CertPEM: certB, KeyPEM: keyB}); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	serialB := serialOf(b.ID)
	if got := served(); got != serialB {
		t.Fatalf("after replacing the certificate: served %s, want B %s", got, serialB)
	}

	// Restore the snapshot taken while A was in place.
	if _, err := st.RestoreFrom(snap); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	if got := served(); got != serialA {
		t.Fatalf("after restoring: served %s, want A %s again", got, serialA)
	}
}
