package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quicgate/internal/engine"
	"quicgate/internal/seal"
	"quicgate/internal/store"
)

// A backup archive holds the database snapshot and the certificate tree and
// nothing else: never the key file, and no secret from the database in
// plaintext. The archive's raw bytes are searched, not query results.
func TestBackupHoldsNoKeyAndNoPlaintextSecret(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	const providerSecret, totpSecret, dnsSecret = "PLAINTEXT-backup-provider-51c2", "PLAINTEXTBACKUPTOTPJBSWY3DP", "PLAINTEXT-backup-dns-88e1"
	p := store.OIDCProvider{Name: "kc", Issuer: "https://sso.example.com/realms/x", ClientID: "c", ClientSecret: providerSecret}
	if err := st.CreateOIDCProvider(&p); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser("admin@example.com", "$2a$10$hash", false); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUserByEmail("admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTPSecret(u.ID, totpSecret); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("acme_dns_config", dnsSecret); err != nil {
		t.Fatal(err)
	}
	keyText, err := os.ReadFile(filepath.Join(dir, seal.KeyFileName))
	if err != nil {
		t.Fatalf("the key file should sit next to the database: %v", err)
	}
	var keyLine string
	for _, l := range strings.Split(string(keyText), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keyLine = l
		}
	}

	s := New(st, engine.New(engine.Config{DisableTLS: true, DataDir: dir}, st), nil, dir)
	var archive bytes.Buffer
	if err := s.writeBackup(&archive); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name != "quicgate.db" && !strings.HasPrefix(h.Name, "certs/") {
			t.Errorf("the archive contains %q: only the database snapshot and certs/ belong in it", h.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		for name, secret := range map[string]string{"provider secret": providerSecret, "two-factor secret": totpSecret, "DNS credentials": dnsSecret, "sealing key": keyLine} {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("%s in the archive holds the %s in plaintext", h.Name, name)
			}
		}
	}
}
