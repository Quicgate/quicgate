package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- the admin identity provider reference fails closed ----

func TestSettingsRejectDanglingAdminOIDCProvider(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	for _, id := range []string{"999999", "not-a-number"} {
		rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"admin_oidc_provider_id": id})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("admin_oidc_provider_id=%q: got %d %s, want 400", id, rr.Code, rr.Body.String())
		}
	}
	if got := s.store.GetSetting("admin_oidc_provider_id", ""); got != "" {
		t.Fatalf("a rejected provider id was stored: %q", got)
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"admin_oidc_provider_id": ""}); rr.Code != http.StatusOK {
		t.Fatalf("clearing the provider: got %d %s, want 200", rr.Code, rr.Body.String())
	}
}

// A provider reference that no longer resolves (a restore, a hand edit) must
// not fall back to the inline issuer: the operator chose a provider, and
// signing in against a different one is not what they configured.
func TestAdminOIDCMissingProviderFailsClosed(t *testing.T) {
	s, _ := adminOIDCServer(t)
	if err := s.store.SetSetting("admin_oidc_provider_id", "999999"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusFound {
		t.Fatalf("login with a missing provider redirected to %q, want an error", rr.Header().Get("Location"))
	}
}

// ---- a login that verified the old password cannot outlive its change ----

func TestLoginRacingPasswordChangeGetsNoSession(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "old-password-1")
	current := login(t, s, "admin@example.com", "old-password-1")

	// racingLogin pauses a login between verifying the password and creating
	// its session, runs between() in that gap, and returns the login response.
	racingLogin := func(between func()) *httptest.ResponseRecorder {
		t.Helper()
		reached, release := make(chan struct{}), make(chan struct{})
		testHookLoginVerified = func() { close(reached); <-release }
		defer func() { testHookLoginVerified = nil }()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			body, _ := json.Marshal(map[string]string{"Email": "admin@example.com", "Password": "old-password-1"})
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
			done <- rr
		}()
		select {
		case <-reached:
		case <-time.After(5 * time.Second):
			t.Fatal("the login never reached the verified state")
		}
		between()
		close(release)
		return <-done
	}

	// Control: with nothing in between, the paused login works.
	ok := racingLogin(func() {})
	if c := sessionFrom(ok); c == "" || call(t, s, http.MethodGet, "/api/hosts", c, nil).Code != http.StatusOK {
		t.Fatalf("control login did not yield a working session: %d %s", ok.Code, ok.Body.String())
	}

	stale := racingLogin(func() {
		rr := call(t, s, http.MethodPost, "/api/password", current,
			map[string]string{"current": "old-password-1", "new": "new-password-2"})
		if rr.Code != http.StatusOK {
			t.Fatalf("password change: %d %s", rr.Code, rr.Body.String())
		}
	})
	if c := sessionFrom(stale); c != "" && call(t, s, http.MethodGet, "/api/hosts", c, nil).Code == http.StatusOK {
		t.Fatal("a login verified against the old password got a working session after the password change")
	}
}

// ---- restore archives: a certs/ entry must be a file under the directory ----

// rawTarEntry builds one ustar member by hand, so a test can produce entries
// archive/tar refuses to write (a regular file whose name ends in a slash).
func rawTarEntry(name string, typeflag byte, data []byte) []byte {
	hdr := make([]byte, 512)
	copy(hdr[0:100], name)
	copy(hdr[100:108], "0000600\x00")
	copy(hdr[108:116], "0000000\x00")
	copy(hdr[116:124], "0000000\x00")
	copy(hdr[124:136], fmt.Sprintf("%011o\x00", len(data)))
	copy(hdr[136:148], fmt.Sprintf("%011o\x00", time.Now().Unix()))
	hdr[156] = typeflag
	copy(hdr[257:263], "ustar\x00")
	copy(hdr[263:265], "00")
	for i := 148; i < 156; i++ {
		hdr[i] = ' '
	}
	sum := 0
	for _, b := range hdr {
		sum += int(b)
	}
	copy(hdr[148:156], fmt.Sprintf("%06o\x00 ", sum))
	body := append([]byte(nil), data...)
	if pad := len(body) % 512; pad != 0 {
		body = append(body, make([]byte, 512-pad)...)
	}
	return append(hdr, body...)
}

func TestRestoreRejectsCertsEntryThatIsNotUnderTheDirectory(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")

	// The database from a real backup of this instance.
	var db []byte
	zr, err := gzip.NewReader(bytes.NewReader(backupArchive(t, s, sess)))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == "quicgate.db" {
			db, _ = io.ReadAll(tr)
		}
	}
	if len(db) == 0 {
		t.Fatal("backup has no database")
	}
	live := filepath.Join(s.dataDir, "certs")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "keep.pem"), []byte("live certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	raw = append(raw, rawTarEntry("quicgate.db", '0', db)...)
	raw = append(raw, rawTarEntry("certs/", '0', []byte("not a directory"))...)
	raw = append(raw, make([]byte, 1024)...)
	var archive bytes.Buffer
	zw := gzip.NewWriter(&archive)
	_, _ = zw.Write(raw)
	_ = zw.Close()

	rr := call(t, s, http.MethodPost, "/api/restore", sess, archive.Bytes())
	if rr.Code == http.StatusOK {
		t.Fatalf("restore accepted a certs/ entry that is a file: %s", rr.Body.String())
	}
	if info, err := os.Stat(live); err != nil || !info.IsDir() {
		t.Fatalf("the live certificate directory was replaced: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(live, "keep.pem")); err != nil || string(got) != "live certificate" {
		t.Fatalf("the live certificates changed: %q %v", got, err)
	}
}

// ---- the log viewer survives an oversized entry ----

func TestLogsSkipOversizedLines(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	dir := filepath.Join(s.dataDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 1100000) // a path over the 1 MiB line buffer
	content := `{"host":"a.test","path":"/before"}` + "\n" +
		`{"host":"a.test","path":"` + long + `"}` + "\n" +
		`{"host":"a.test","path":"/after-attack"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "access.log"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := call(t, s, http.MethodGet, "/api/logs?n=50", sess, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("logs: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/before") || !strings.Contains(body, "/after-attack") {
		t.Fatalf("an oversized entry hid the entries around it: %.200s", body)
	}
}
