package store

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quicgate/internal/seal"
)

// Distinctive values, so a raw-byte search of the files cannot match by chance.
const (
	secOIDCSetting = "PLAINTEXT-oidc-setting-7f3a91"
	secDNS         = `{"account":"PLAINTEXT-dns-cred-b20c44"}`
	secCookie      = "504c41494e544558542d636f6f6b69652d73656372657430303030303030303030" // hex, 32+ bytes
	secProvider    = "PLAINTEXT-provider-secret-e91d07"
	secTOTP        = "PLAINTEXTTOTPJBSWY3DPEHPK3PXP"
)

func noKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
}

// legacyDB builds a database the way a version before sealing left it: every
// secret in plaintext, and no key file next to it.
func legacyDB(t *testing.T) (dir, path, keyPEM string) {
	t.Helper()
	noKeyEnv(t)
	dir = t.TempDir()
	path = filepath.Join(dir, "quicgate.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser("admin@example.com", "$2a$10$hash", false); err != nil {
		t.Fatal(err)
	}
	cert, err := st.GenerateSelfSigned("legacy", []string{"legacy.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM, err = st.GetCustomCertPEM(cert.ID)
	if err != nil || !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatalf("self-signed key: %v", err)
	}
	st.Close()
	if err := os.Remove(filepath.Join(dir, seal.KeyFileName)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"quicgate.db-wal", "quicgate.db-shm"} {
		_ = os.Remove(filepath.Join(dir, f))
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{"INSERT OR REPLACE INTO settings (key, value) VALUES ('oidc_client_secret', ?)", []any{secOIDCSetting}},
		{"INSERT OR REPLACE INTO settings (key, value) VALUES ('acme_dns_config', ?)", []any{secDNS}},
		{"INSERT OR REPLACE INTO settings (key, value) VALUES ('sso_cookie_secret', ?)", []any{secCookie}},
		{"INSERT OR REPLACE INTO settings (key, value) VALUES ('acme_email', 'ops@example.com')", nil},
		{"INSERT INTO oidc_providers (name, issuer, client_id, client_secret) VALUES ('kc', 'https://sso.example.com/realms/x', 'quicgate', ?)", []any{secProvider}},
		{"UPDATE users SET totp_secret = ?", []any{secTOTP}},
		{"UPDATE custom_certs SET key_pem = ?", []any{keyPEM}},
	} {
		if _, err := db.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.q, err)
		}
	}
	return dir, path, keyPEM
}

func rawContains(t *testing.T, dir string, needles ...string) []string {
	t.Helper()
	var hits []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == seal.KeyFileName {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if bytes.Contains(data, []byte(n)) {
				hits = append(hits, e.Name()+" contains "+n[:24])
			}
		}
	}
	return hits
}

// Opening a database from before sealing seals every secret, keeps them
// readable, and leaves no plaintext in the database file, its WAL, or a backup
// snapshot. SQL results prove nothing here, so the files' raw bytes are read.
func TestMigrationSealsEverySecretAndScrubsTheFiles(t *testing.T) {
	dir, path, keyPEM := legacyDB(t)
	keyBody := strings.Split(keyPEM, "\n")[1] // first base64 line of the PEM key
	needles := []string{secOIDCSetting, "PLAINTEXT-dns-cred-b20c44", secCookie, secProvider, secTOTP, keyBody}
	if hits := rawContains(t, dir, needles...); len(hits) != len(needles) {
		t.Fatalf("the legacy database should hold all %d secrets in plaintext, found %v", len(needles), hits)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s := st.SealStatus(); s.Locked || s.KeyID == "" {
		t.Fatalf("status after migration = %+v", s)
	}
	// Still readable through the store.
	if got := st.GetSetting("oidc_client_secret", ""); got != secOIDCSetting {
		t.Errorf("oidc_client_secret = %q", got)
	}
	if got := st.GetSetting("acme_dns_config", ""); got != secDNS {
		t.Errorf("acme_dns_config = %q", got)
	}
	if got := st.GetSetting("acme_email", ""); got != "ops@example.com" {
		t.Errorf("an ordinary setting changed: %q", got)
	}
	provs, err := st.ListOIDCProviders()
	if err != nil || len(provs) != 1 || provs[0].ClientSecret != secProvider {
		t.Fatalf("providers = %+v, %v", provs, err)
	}
	u, err := st.GetUserByEmail("admin@example.com")
	if err != nil || u.TOTPSecret != secTOTP {
		t.Fatalf("user = %+v, %v", u, err)
	}
	certs, _ := st.ListCustomCerts()
	if _, k, err := st.GetCustomCertPEM(certs[0].ID); err != nil || k != keyPEM {
		t.Fatalf("custom cert key did not survive: %v", err)
	}
	// Sealed in the rows.
	var raw string
	for _, q := range []string{
		"SELECT value FROM settings WHERE key='oidc_client_secret'",
		"SELECT value FROM settings WHERE key='sso_cookie_secret'",
		"SELECT client_secret FROM oidc_providers",
		"SELECT totp_secret FROM users",
		"SELECT key_pem FROM custom_certs",
	} {
		if err := st.db.QueryRow(q).Scan(&raw); err != nil || !seal.IsSealed(raw) {
			t.Errorf("%s = %.30q (%v), want a sealed value", q, raw, err)
		}
	}

	snap := filepath.Join(dir, "snapshot.db")
	if err := st.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	if hits := rawContains(t, dir, needles...); len(hits) > 0 {
		t.Fatalf("plaintext left in the files after sealing (live database, WAL, or snapshot): %v", hits)
	}
	st.Close()
	if hits := rawContains(t, dir, needles...); len(hits) > 0 {
		t.Fatalf("plaintext left in the files after closing: %v", hits)
	}

	// A second start finds nothing to do and the same key.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if n, warnings, err := again.sealExisting(); err != nil || n != 0 || len(warnings) != 0 {
		t.Fatalf("second start resealed %d values (%v, %v), want 0", n, warnings, err)
	}
}

// With the key gone the store is locked: nothing opens, nothing is replaced,
// no new key is invented, and two-factor is never read as switched off.
func TestMissingKeyLocksAndReplacesNothing(t *testing.T) {
	dir, path, _ := legacyDB(t)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	keyFile := filepath.Join(dir, seal.KeyFileName)
	saved, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}

	locked, err := Open(path)
	if err != nil {
		t.Fatalf("a missing key must not stop quicgate from starting: %v", err)
	}
	if s := locked.SealStatus(); !s.Locked || s.Reason == "" {
		t.Fatalf("status = %+v, want locked with a reason", s)
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("a new key file was invented while sealed secrets exist")
	}
	if _, err := locked.GetUserByEmail("admin@example.com"); err == nil {
		t.Fatal("the account was returned although its two-factor secret cannot be opened: a login would skip 2FA")
	}
	if got := locked.GetSetting("oidc_client_secret", ""); got != "" {
		t.Fatalf("locked secret setting read as %q", got)
	}
	if provs, err := locked.ListOIDCProviders(); err != nil || len(provs) != 1 || provs[0].ClientSecret != "" {
		t.Fatalf("locked provider = %+v, %v: want it listed with no usable secret", provs, err)
	}
	certs, _ := locked.ListCustomCerts()
	if _, _, err := locked.GetCustomCertPEM(certs[0].ID); err == nil {
		t.Fatal("a locked certificate key was returned")
	}
	if got := locked.GetSetting("acme_email", ""); got != "ops@example.com" {
		t.Fatalf("ordinary settings must keep working when locked, got %q", got)
	}
	// Nothing can be replaced by accident.
	if err := locked.SetSetting("sso_cookie_secret", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("a locked store accepted a new secret, which could only be stored in plaintext")
	}
	if err := locked.SetTOTPSecret(1, "NEWSECRET"); err == nil {
		t.Fatal("a locked store accepted a new two-factor secret")
	}
	p := OIDCProvider{ID: 1, Name: "kc", Issuer: "https://sso.example.com/realms/x", ClientID: "renamed"}
	if err := locked.UpdateOIDCProvider(&p); err != nil {
		t.Fatalf("editing a provider without touching its secret must work when locked: %v", err)
	}
	var raw string
	if err := locked.db.QueryRow("SELECT client_secret FROM oidc_providers").Scan(&raw); err != nil || !seal.IsSealed(raw) {
		t.Fatalf("the sealed provider secret was not kept: %.20q %v", raw, err)
	}
	locked.Close()

	// The key comes back: everything opens again, untouched.
	if err := os.WriteFile(keyFile, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	back, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	if u, err := back.GetUserByEmail("admin@example.com"); err != nil || u.TOTPSecret != secTOTP {
		t.Fatalf("after the key returned: %+v, %v", u, err)
	}
	if provs, _ := back.ListOIDCProviders(); provs[0].ClientSecret != secProvider || provs[0].ClientID != "renamed" {
		t.Fatalf("after the key returned: %+v", provs[0])
	}
}

// A key that is not the one that sealed the secrets locks the store too,
// instead of sealing new values under a second key.
func TestWrongKeyLocks(t *testing.T) {
	_, path, _ := legacyDB(t)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	t.Setenv("QG_SECRET_KEY", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	wrong, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if s := wrong.SealStatus(); !s.Locked {
		t.Fatalf("status with a foreign key = %+v, want locked", s)
	}
	if err := wrong.SetSetting("oidc_client_secret", "new"); err == nil {
		t.Fatal("a store with a foreign key sealed a new value under it")
	}
}

// A ciphertext copied to another row does not open there.
func TestSealedValueDoesNotOpenInAnotherRow(t *testing.T) {
	noKeyEnv(t)
	st, err := Open(filepath.Join(t.TempDir(), "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := OIDCProvider{Name: "a", Issuer: "https://a.example.com", ClientID: "a", ClientSecret: "secret-of-a"}
	b := OIDCProvider{Name: "b", Issuer: "https://b.example.com", ClientID: "b", ClientSecret: "secret-of-b"}
	if err := st.CreateOIDCProvider(&a); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOIDCProvider(&b); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE oidc_providers SET client_secret = (SELECT client_secret FROM oidc_providers WHERE id = ?) WHERE id = ?", a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	provs, err := st.ListOIDCProviders()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range provs {
		if p.ID == b.ID && p.ClientSecret != "" {
			t.Fatalf("provider b opened provider a's ciphertext as %q", p.ClientSecret)
		}
		if p.ID == a.ID && p.ClientSecret != "secret-of-a" {
			t.Fatalf("provider a = %q", p.ClientSecret)
		}
	}
}

// Unseal turns the database back into what an older version can read, and the
// next start seals it again.
func TestUnsealForRollback(t *testing.T) {
	_, path, _ := legacyDB(t)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.Unseal()
	if err != nil || n != 6 {
		t.Fatalf("Unseal = %d, %v, want 6 values", n, err)
	}
	var raw string
	if err := st.db.QueryRow("SELECT totp_secret FROM users").Scan(&raw); err != nil || raw != secTOTP {
		t.Fatalf("after unseal the column holds %.20q, want the plaintext an old version reads", raw)
	}
	st.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.db.QueryRow("SELECT totp_secret FROM users").Scan(&raw); err != nil || !seal.IsSealed(raw) {
		t.Fatalf("the next start did not seal again: %.20q", raw)
	}
}

// keyIDOf returns the key id a sealed value names.
func keyIDOf(sealed string) string {
	parts := strings.SplitN(sealed, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// keyLine returns the key from a key file, without the comment.
func keyLine(t *testing.T, path string) string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(text), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	t.Fatal("no key in the key file")
	return ""
}

// The VPN refresh tokens are part of the seal inventory: a key rotation seals
// them under the new key and -unseal writes them back, like every other
// secret. Their writer sealed them, bound to the session's provider and
// subject, but the migration did not know the column, so a rotation left
// them under the retired key and -unseal left them sealed.
func TestRefreshTokensFollowKeyRotation(t *testing.T) {
	noKeyEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "quicgate.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const token = "PLAINTEXT-refresh-token-5a1c93"
	now := time.Now()
	sess := &VPNSession{Provider: 7, Sub: "alice", Email: "alice@example.com", RefreshToken: token,
		LoginAt: now, RenewedAt: now, LeaseUntil: now.Add(time.Hour), GraceUntil: now.Add(2 * time.Hour), HardUntil: now.Add(24 * time.Hour)}
	if err := st.LoginVPNSession(sess); err != nil {
		t.Fatal(err)
	}
	oldID := st.box.PrimaryID()
	var raw string
	if err := st.db.QueryRow("SELECT refresh_token FROM vpn_sessions").Scan(&raw); err != nil || keyIDOf(raw) != oldID {
		t.Fatalf("the token was not sealed under the key: %.30q %v", raw, err)
	}
	st.Close()

	// Rotate: a new primary key, the old one kept for opening.
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QG_SECRET_KEY", base64.StdEncoding.EncodeToString(fresh)+"\n"+keyLine(t, filepath.Join(dir, seal.KeyFileName)))
	rotated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	status := rotated.SealStatus()
	if status.Locked || status.KeyID == oldID || len(status.Warnings) != 0 {
		t.Fatalf("status after rotation = %+v", status)
	}
	if err := rotated.db.QueryRow("SELECT refresh_token FROM vpn_sessions").Scan(&raw); err != nil || keyIDOf(raw) != status.KeyID {
		t.Fatalf("the refresh token stayed under the retired key %s: %.30q (primary %s)", keyIDOf(raw), raw, status.KeyID)
	}
	got, err := rotated.GetVPNSession(7, "alice")
	if err != nil || got.RefreshToken != token {
		t.Fatalf("after rotation the token reads as %q, %v", got.RefreshToken, err)
	}
	if n, err := rotated.Unseal(); err != nil || n != 1 {
		t.Fatalf("Unseal = %d, %v, want the one token", n, err)
	}
	if err := rotated.db.QueryRow("SELECT refresh_token FROM vpn_sessions").Scan(&raw); err != nil || raw != token {
		t.Fatalf("after -unseal the column holds %.30q, want the plaintext token", raw)
	}
	rotated.Close()
}

// One value that does not open (damaged, or copied from another row) must not
// keep every other secret under the retired key or in plaintext: the migration
// seals what it can, leaves that value as it is, and says so in the status
// instead of aborting and reporting "sealed".
func TestMigrationSealsTheRestWhenOneValueIsDamaged(t *testing.T) {
	dir, path, _ := legacyDB(t)
	st, err := Open(path) // seals everything under the key it creates
	if err != nil {
		t.Fatal(err)
	}
	oldID := st.box.PrimaryID()
	// A ciphertext moved to another row does not open there. It needs
	// re-sealing at the next rotation, like everything else under this key,
	// and that is when it fails.
	if _, err := st.db.Exec("UPDATE users SET totp_secret = (SELECT client_secret FROM oidc_providers LIMIT 1)"); err != nil {
		t.Fatal(err)
	}
	var moved string
	if err := st.db.QueryRow("SELECT totp_secret FROM users").Scan(&moved); err != nil {
		t.Fatal(err)
	}
	// And a plaintext secret is waiting to be sealed for the first time.
	const dns = `{"account":"PLAINTEXT-dns-cred-second-9c1e"}`
	if _, err := st.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('acme_dns_config', ?)", dns); err != nil {
		t.Fatal(err)
	}
	st.Close()

	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QG_SECRET_KEY", base64.StdEncoding.EncodeToString(fresh)+"\n"+keyLine(t, filepath.Join(dir, seal.KeyFileName)))
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	status := again.SealStatus()
	if status.Locked || status.KeyID == oldID {
		t.Fatalf("status after rotation = %+v", status)
	}
	if len(status.Warnings) != 1 || !strings.Contains(status.Warnings[0], "users.totp_secret 1") {
		t.Fatalf("warnings = %v, want the damaged value named", status.Warnings)
	}
	var raw string
	for _, q := range []string{
		"SELECT value FROM settings WHERE key='acme_dns_config'",
		"SELECT value FROM settings WHERE key='oidc_client_secret'",
		"SELECT client_secret FROM oidc_providers",
		"SELECT key_pem FROM custom_certs",
	} {
		if err := again.db.QueryRow(q).Scan(&raw); err != nil || keyIDOf(raw) != status.KeyID {
			t.Errorf("%s: %.30q (%v) is not under the new key %s: one damaged value stopped the rest", q, raw, err, status.KeyID)
		}
	}
	if got := again.GetSetting("acme_dns_config", ""); got != dns {
		t.Fatalf("acme_dns_config = %q", got)
	}
	if err := again.db.QueryRow("SELECT totp_secret FROM users").Scan(&raw); err != nil || raw != moved {
		t.Fatalf("the damaged value was not kept as it was: %.30q %v", raw, err)
	}
	if n, warnings, err := again.sealExisting(); err != nil || n != 0 || len(warnings) != 1 {
		t.Fatalf("a second pass: n=%d warnings=%v err=%v", n, warnings, err)
	}
}

// Restoring a backup from before sealing seals what it brings in; restoring
// one that another key sealed keeps those values untouched and says so.
func TestRestoreSealsOldBackupsAndReportsForeignKeys(t *testing.T) {
	legacyDir, legacyPath, _ := legacyDB(t) // plaintext, like a backup made by an older version
	_ = legacyDir

	noKeyEnv(t)
	liveDir := t.TempDir()
	live, err := Open(filepath.Join(liveDir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	warnings, err := live.RestoreFrom(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "sealed with key") {
			t.Fatalf("a plaintext backup produced a foreign-key warning: %s", w)
		}
	}
	if u, err := live.GetUserByEmail("admin@example.com"); err != nil || u.TOTPSecret != secTOTP {
		t.Fatalf("restored account = %+v, %v", u, err)
	}
	var raw string
	if err := live.db.QueryRow("SELECT totp_secret FROM users").Scan(&raw); err != nil || !seal.IsSealed(raw) {
		t.Fatalf("restored secret was left in plaintext: %.20q", raw)
	}
	if hits := rawContains(t, liveDir, secTOTP, secProvider, secOIDCSetting); len(hits) > 0 {
		t.Fatalf("plaintext from the restored backup is left in the files: %v", hits)
	}

	// A backup sealed by another instance's key.
	otherDir := t.TempDir()
	other, err := Open(filepath.Join(otherDir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	p := OIDCProvider{Name: "kc", Issuer: "https://sso.example.com/realms/x", ClientID: "c", ClientSecret: "foreign-secret"}
	if err := other.CreateOIDCProvider(&p); err != nil {
		t.Fatal(err)
	}
	if err := other.CreateUser("admin@example.com", "$2a$10$hash", false); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(otherDir, "snap.db")
	if err := other.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	other.Close()
	warnings, err = live.RestoreFrom(snap)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		found = found || strings.Contains(w, "sealed with key")
	}
	if !found {
		t.Fatalf("restoring secrets sealed by another key gave no warning: %v", warnings)
	}
	if err := live.db.QueryRow("SELECT client_secret FROM oidc_providers").Scan(&raw); err != nil || !seal.IsSealed(raw) {
		t.Fatalf("the foreign sealed value was not kept as it was: %.20q", raw)
	}
	if provs, _ := live.ListOIDCProviders(); len(provs) != 1 || provs[0].ClientSecret != "" {
		t.Fatalf("a secret sealed by a foreign key must read as unusable, got %+v", provs)
	}
}
