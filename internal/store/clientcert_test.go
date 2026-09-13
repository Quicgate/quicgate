package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Q01: a client-certificate policy must be enforceable, or it is refused.
func TestHostValidateClientCert(t *testing.T) {
	good := testCAPEM(t)
	base := func() Host {
		return Host{Type: "proxy", Domains: []string{"mtls.test"}, CertMode: "auto",
			Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}
	}
	cases := []struct {
		name    string
		mutate  func(*Host)
		wantErr string
	}{
		{"valid require", func(h *Host) { h.Options.ClientCert = &ClientCert{Mode: "require", CAPEM: good} }, ""},
		{"valid request", func(h *Host) { h.Options.ClientCert = &ClientCert{Mode: "request", CAPEM: good} }, ""},
		{"empty mode means require", func(h *Host) { h.Options.ClientCert = &ClientCert{CAPEM: good} }, ""},
		{"unknown mode", func(h *Host) { h.Options.ClientCert = &ClientCert{Mode: "sometimes", CAPEM: good} }, "mode"},
		{"empty bundle", func(h *Host) { h.Options.ClientCert = &ClientCert{Mode: "require"} }, "CA certificate"},
		{"garbage bundle", func(h *Host) { h.Options.ClientCert = &ClientCert{Mode: "require", CAPEM: "nope"} }, "CA certificate"},
		{"truncated certificate", func(h *Host) {
			h.Options.ClientCert = &ClientCert{Mode: "require", CAPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}
		}, "CA certificate"},
		{"plain http host", func(h *Host) {
			h.CertMode = "none"
			h.Options.ClientCert = &ClientCert{Mode: "require", CAPEM: good}
		}, "require TLS"},
	}
	for _, tc := range cases {
		h := base()
		tc.mutate(&h)
		err := h.Validate()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: got %v, want an error mentioning %q", tc.name, err, tc.wantErr)
		}
		if tc.name == "empty mode means require" && err == nil && h.Options.ClientCert.Mode != "require" {
			t.Errorf("empty mode normalised to %q, want require", h.Options.ClientCert.Mode)
		}
	}
}
