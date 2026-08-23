package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A restore upload must not be able to expand without bound: the compressed
// size limit says nothing about what gzip unpacks to, so a few megabytes of
// zeroes could otherwise fill the data volume.
func TestRestoreRejectsDecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	size := int64(maxRestoreExpandedBytes) + (1 << 20)
	if err := tw.WriteHeader(&tar.Header{Name: "quicgate.db", Mode: 0o600, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	// Zeroes compress to almost nothing, which is the whole point of the attack.
	chunk := make([]byte, 1<<20)
	for written := int64(0); written < size; written += int64(len(chunk)) {
		n := int64(len(chunk))
		if remaining := size - written; remaining < n {
			n = remaining
		}
		if _, err := tw.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	t.Logf("compressed upload: %d bytes, declared expansion: %d bytes", buf.Len(), size)

	s := newTestServer(t)
	tok := "restore-session"
	s.sessions[tok] = session{userID: 1, email: "admin@example.com", expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(buf.Bytes()))
	req.AddCookie(&http.Cookie{Name: "qg_session", Value: tok})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bomb upload = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "size limit") {
		t.Fatalf("unexpected rejection reason: %s", rr.Body.String())
	}
}

// Symlink members have no place in a backup and must not be honoured.
func TestRestoreRejectsNonRegularMembers(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "certs/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777,
	}); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()

	s := newTestServer(t)
	tok := "restore-session-2"
	s.sessions[tok] = session{userID: 1, email: "admin@example.com", expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(buf.Bytes()))
	req.AddCookie(&http.Cookie{Name: "qg_session", Value: tok})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("symlink member = %d, want 400: %s", rr.Code, rr.Body.String())
	}
}
