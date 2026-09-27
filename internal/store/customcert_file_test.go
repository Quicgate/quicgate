package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// certFiles writes a valid self-signed pair to dir and returns the two paths.
func certFiles(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	certPEM, keyPEM, err := selfSignedPEM([]string{"file.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// Importing a certificate from a path reads what an administrator named, as
// root: the file must be a regular file of a sane size (a directory, a device
// or an oversized file is refused before it is read), and the error names the
// path that was given and nothing else about the filesystem.
func TestImportCertFromFileRefusesOddFiles(t *testing.T) {
	st := openTestStore(t)
	dir := t.TempDir()
	cert, key := certFiles(t, dir)
	if _, err := st.ImportCertFromFile("ok", cert, key); err != nil {
		t.Fatalf("a regular pair: %v", err)
	}

	if _, err := st.ImportCertFromFile("dir", dir, key); err == nil || !strings.Contains(err.Error(), "certificate file "+dir+" is not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, bytes.Repeat([]byte("A"), 600<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ImportCertFromFile("big", cert, big); err == nil || !strings.Contains(err.Error(), "key file "+big+" is larger than 512 KiB") {
		t.Errorf("an oversized key: %v", err)
	}
	if _, err := st.ImportCertFromFile("missing", "nope.pem", key); err == nil ||
		!strings.Contains(err.Error(), "certificate file nope.pem does not exist") || strings.Contains(err.Error(), "no such file") {
		t.Errorf("a missing file must be reported by the path given, without the OS text: %v", err)
	}
	if _, err := st.ImportCertFromFile("empty", "", key); err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Errorf("an empty path: %v", err)
	}
	if fi, err := os.Stat("/dev/null"); err == nil && !fi.Mode().IsRegular() {
		if _, err := st.ImportCertFromFile("dev", "/dev/null", key); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("a device: %v", err)
		}
	}
	// A symbolic link to a regular file is fine: certbot's live/ directory is
	// made of them.
	link := filepath.Join(dir, "live.pem")
	if err := os.Symlink(cert, link); err == nil {
		if _, err := st.ImportCertFromFile("link", link, key); err != nil {
			t.Errorf("a symlink to a regular file: %v", err)
		}
	}
	certs, _ := st.ListCustomCerts()
	for _, c := range certs {
		if c.Name != "ok" && c.Name != "link" {
			t.Errorf("a refused import was stored: %+v", c)
		}
	}
}
