package engine

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"quicgate/internal/store"
)

func sealKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// openEngineAt opens the database at path with the sealing key in use and
// returns an engine on it that is closed with the test.
func openEngineAt(t *testing.T, dir string) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	e := New(Config{DisableTLS: true, DataDir: dir}, st)
	return e, st
}

func closeEngine(e *Engine, st *store.Store) {
	e.wg.Close()
	_ = e.accessLog.Close()
	_ = e.ban.closePersist()
	_ = st.Close()
}

// A database that holds a server key this instance cannot open (a restore
// under another sealing key) keeps that key, byte for byte, through reloads
// and restarts. quicgate used to read "cannot open" as "first use" and made a
// new key over it, after which the right sealing key could no longer bring
// the old one back (QG-04).
func TestAnUnreadableServerKeyIsNeverReplaced(t *testing.T) {
	t.Setenv("QG_SECRET_KEY_FILE", "")
	keyA, keyB := sealKey(t), sealKey(t)
	dir := t.TempDir()
	port := fmt.Sprint(freeUDP(t))

	t.Setenv("QG_SECRET_KEY", keyA)
	e, st := openEngineAt(t, dir)
	setSettings(t, st, map[string]string{"wg_enabled": "1", "wg_port": port})
	reload(t, e)
	original := e.WGStatus().PublicKey
	if original == "" || !e.WGStatus().Running {
		t.Fatalf("the endpoint did not start: %+v", e.WGStatus())
	}
	sealedBefore := rawSetting(t, e, "wg_private_key")
	closeEngine(e, st)

	// The same database under another sealing key: what a restore onto a new
	// machine looks like.
	t.Setenv("QG_SECRET_KEY", keyB)
	e, st = openEngineAt(t, dir)
	for i := 0; i < 3; i++ {
		reload(t, e)
	}
	status := e.WGStatus()
	if status.Running || !status.KeyUnreadable || !strings.Contains(status.Error, "cannot be opened") {
		t.Fatalf("with a server key it cannot open, the endpoint must stay down and say why: %+v", status)
	}
	if got := rawSetting(t, e, "wg_private_key"); got != sealedBefore {
		t.Fatal("the stored server key was replaced although it could not be read")
	}
	closeEngine(e, st)

	// The right sealing key comes back: so does the server's identity.
	t.Setenv("QG_SECRET_KEY", keyA)
	e, st = openEngineAt(t, dir)
	reload(t, e)
	if got := e.WGStatus(); got.PublicKey != original || !got.Running || got.KeyUnreadable {
		t.Fatalf("with the original sealing key: %+v, want the original public key %s", got, original)
	}
	closeEngine(e, st)

	// A fresh installation still makes its key.
	t.Setenv("QG_SECRET_KEY", keyB)
	e, st = openEngineAt(t, t.TempDir())
	defer closeEngine(e, st)
	setSettings(t, st, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(freeUDP(t))})
	reload(t, e)
	if got := e.WGStatus(); !got.Running || got.PublicKey == "" || got.PublicKey == original {
		t.Fatalf("a fresh installation: %+v", got)
	}
}
