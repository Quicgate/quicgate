package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func tokenTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A token is what it was made as, and says so by how it starts.
func TestTokenKeepsItsAccessLevel(t *testing.T) {
	st := tokenTestStore(t)
	for access, prefix := range map[string]string{TokenFull: "qg_", TokenMonitor: "qgm_", TokenSwitch: "qgs_"} {
		tok, err := st.CreateAPITokenFor("t-"+access, access)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok.Token, prefix) {
			t.Errorf("a %s token starts %q, want %q", access, tok.Token[:5], prefix)
		}
		if got, ok := st.TokenAccess(tok.Token); !ok || got != access {
			t.Errorf("a %s token reads as %q (valid %v)", access, got, ok)
		}
	}
	if _, err := st.CreateAPITokenFor("typo", "admin"); err == nil {
		t.Error("a token with a made-up access level was created")
	}
	if _, ok := st.TokenAccess("qg_" + strings.Repeat("0", 64)); ok {
		t.Error("a token nobody made is valid")
	}
}

// A limited token cannot be passed off as a full one by changing how it starts.
func TestLimitedTokenCannotClaimMore(t *testing.T) {
	st := tokenTestStore(t)
	mon, err := st.CreateAPITokenFor("dashboard", TokenMonitor)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimPrefix(mon.Token, "qgm_")
	for _, forged := range []string{"qg_" + secret, "qgs_" + secret, secret} {
		if access, ok := st.TokenAccess(forged); ok {
			t.Errorf("%s... is valid as %q", forged[:4], access)
		}
	}
}

// A quicgate from before access levels looks a token up by the plain hash of
// what it was sent and reads every hit as full access. After a downgrade a
// limited token has to match nothing there.
func TestLimitedTokenIsUnknownToAnOlderVersion(t *testing.T) {
	st := tokenTestStore(t)
	for _, access := range []string{TokenMonitor, TokenSwitch} {
		tok, err := st.CreateAPITokenFor("limited", access)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(tok.Token))
		var n int
		if err := st.db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE hash=?", hex.EncodeToString(sum[:])).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("an older version would accept a %s token, as full access", access)
		}
	}
	// A full token is stored the way it always was, so those keep working
	// across an upgrade and a downgrade.
	full, _ := st.CreateAPIToken("script")
	sum := sha256.Sum256([]byte(full.Token))
	var n int
	_ = st.db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE hash=?", hex.EncodeToString(sum[:])).Scan(&n)
	if n != 1 {
		t.Error("a full token is no longer stored under its plain hash")
	}
}

// A token from before access levels existed could do everything, and still can.
func TestTokensFromBeforeAccessLevelsAreFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quicgate.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	raw := "qg_" + strings.Repeat("ab", 32)
	sum := sha256.Sum256([]byte(raw))
	for _, stmt := range []string{
		"DROP TABLE api_tokens",
		"CREATE TABLE api_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL)",
		"INSERT INTO api_tokens (name, hash, created_at) VALUES ('old', '" + hex.EncodeToString(sum[:]) + "', '2026-01-01T00:00:00Z')",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatalf("opening a database from before access levels: %v", err)
	}
	defer st.Close()
	if access, ok := st.TokenAccess(raw); !ok || access != TokenFull {
		t.Errorf("an old token reads as %q (valid %v), want full", access, ok)
	}
	list, _ := st.ListAPITokens()
	if len(list) != 1 || list[0].Access != TokenFull {
		t.Errorf("the token list reads %+v", list)
	}
}

// A row that names one level under a hash made for another is no token. The
// interface cannot make such a row; a database edited by hand, or a restore
// gone wrong, can.
func TestTokenRowMustAgreeWithItsHash(t *testing.T) {
	st := tokenTestStore(t)
	raw := "qg_" + strings.Repeat("cd", 32)
	if _, err := st.db.Exec("INSERT INTO api_tokens (name, hash, access, created_at) VALUES ('odd', ?, 'monitor', '2026-01-01T00:00:00Z')", hashToken(raw, TokenFull)); err != nil {
		t.Fatal(err)
	}
	if access, ok := st.TokenAccess(raw); ok {
		t.Errorf("a full-looking token stored as monitor is valid as %q", access)
	}
}
