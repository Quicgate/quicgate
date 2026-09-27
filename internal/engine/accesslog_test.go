package engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Client-controlled fields are cut before a record is queued or written, so a
// request with a megabyte of User-Agent takes neither a megabyte of the queue
// nor of the file, and what remains is still valid text.
func TestAccessLogClipsClientFields(t *testing.T) {
	dir := t.TempDir()
	l := newAccessLogger(dir)
	h := l.wrap(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	long := strings.Repeat("a", 10000)
	r := httptest.NewRequest(http.MethodGet, "http://x.test/"+long, nil)
	r.Host = long + ".test"
	r.Header.Set("User-Agent", strings.Repeat("€", 5000)) // three bytes each: 512 falls inside a character
	r.RemoteAddr = "203.0.113.9:1"
	h(httptest.NewRecorder(), r)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "logs", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	var rec accessRecord
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatalf("%v in %q", err, data)
	}
	if len(rec.Host) != logMaxHost || !strings.HasPrefix(rec.Host, "aaa") {
		t.Errorf("host logged as %d bytes, want %d", len(rec.Host), logMaxHost)
	}
	if len(rec.Path) != logMaxPath || !strings.HasPrefix(rec.Path, "/aaa") {
		t.Errorf("path logged as %d bytes, want %d", len(rec.Path), logMaxPath)
	}
	if len(rec.UA) > logMaxUA || len(rec.UA) <= logMaxUA-utf8.UTFMax || !utf8.ValidString(rec.UA) || !strings.HasSuffix(rec.UA, "€") {
		t.Errorf("user agent logged as %d bytes ending %q, want at most %d and whole characters", len(rec.UA), rec.UA[len(rec.UA)-3:], logMaxUA)
	}
	if rec.ClientIP != "203.0.113.9" || rec.Status != http.StatusOK {
		t.Errorf("record %+v: the other fields are wrong", rec)
	}

	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"Mozilla/5.0", 512, "Mozilla/5.0"},
		{"abcdef", 6, "abcdef"},
		{"abcdef", 4, "abcd"},
		{"aé", 2, "a"},
		{"", 4, ""},
	} {
		if got := clipField(c.in, c.n); got != c.want {
			t.Errorf("clipField(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
