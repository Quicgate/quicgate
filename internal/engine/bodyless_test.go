package engine

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"
	"time"

	"quicgate/internal/store"
)

// quicBody mimics an HTTP/3 request body. The crucial property is that it does
// NOT report EOF immediately: quic-go hands the handler a live stream, so
// http.Transport's empty-body probe (200ms) times out and falls back to chunked
// framing. A bytes.Reader would EOF instantly and the probe would suppress
// chunking on its own, hiding the bug.
type quicBody struct{ once sync.Once }

func (b *quicBody) Read([]byte) (int, error) {
	b.once.Do(func() { time.Sleep(350 * time.Millisecond) })
	return 0, io.EOF
}
func (b *quicBody) Close() error { return nil }

// h3Request builds the request shape quic-go produces for a bodyless HTTP/3
// GET: ContentLength -1 (no content-length header was sent) plus a non-nil
// stream body.
func h3Request(method, host, path string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = "10.0.0.5:50000"
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/3.0", 3, 0
	r.ContentLength = -1
	r.Body = &quicBody{}
	return r
}

// TestNormalizeBodyless is the deterministic contract test: GET/HEAD with an
// unknown-length body must be rewritten to an explicit empty body, while
// methods that can legitimately stream are left untouched.
func TestNormalizeBodyless(t *testing.T) {
	newPR := func(method string, contentLength int64) *httputil.ProxyRequest {
		in := httptest.NewRequest(method, "http://x.test/", nil)
		out := in.Clone(context.Background())
		out.ContentLength = contentLength
		out.Body = io.NopCloser(bytes.NewReader(nil))
		return &httputil.ProxyRequest{In: in, Out: out}
	}

	t.Run("GET unknown length is normalized", func(t *testing.T) {
		pr := newPR(http.MethodGet, -1)
		normalizeBodyless(pr)
		if pr.Out.ContentLength != 0 {
			t.Errorf("ContentLength = %d, want 0", pr.Out.ContentLength)
		}
		if pr.Out.Body != http.NoBody {
			t.Error("Body was not replaced with http.NoBody, so the transport can still chunk it")
		}
	})

	t.Run("HEAD unknown length is normalized", func(t *testing.T) {
		pr := newPR(http.MethodHead, -1)
		normalizeBodyless(pr)
		if pr.Out.ContentLength != 0 || pr.Out.Body != http.NoBody {
			t.Errorf("HEAD not normalized: len=%d bodyIsNoBody=%v", pr.Out.ContentLength, pr.Out.Body == http.NoBody)
		}
	})

	t.Run("POST unknown length is left alone", func(t *testing.T) {
		pr := newPR(http.MethodPost, -1)
		normalizeBodyless(pr)
		if pr.Out.ContentLength != -1 || pr.Out.Body == http.NoBody {
			t.Error("POST body must stay streamable; unknown-length uploads must not be dropped")
		}
	})

	t.Run("GET with a known length is left alone", func(t *testing.T) {
		pr := newPR(http.MethodGet, 11)
		normalizeBodyless(pr)
		if pr.Out.ContentLength != 11 || pr.Out.Body == http.NoBody {
			t.Error("a GET with a real declared body must be preserved")
		}
	})
}

// TestBodylessRequestNotChunked is the end-to-end regression test for the
// h3 -> 400 bug: a strict upstream (lighttpd on Asustor ADM) rejects a chunked
// GET with 400 Bad Request for every path, so HTTP/3 browsing broke while curl
// over HTTP/1.1 kept working.
func TestBodylessRequestNotChunked(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			var mu sync.Mutex
			var gotTE []string
			up := backend(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				gotTE = r.TransferEncoding
				mu.Unlock()
				// A strict upstream refuses a chunked bodyless request outright.
				if len(r.TransferEncoding) > 0 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, "ok")
			})

			e, st := newTestEngine(t)
			if err := st.CreateHost(&store.Host{
				Type: "proxy", Domains: []string{"h3.test"}, CertMode: "none", Enabled: true,
				Upstream: up,
			}); err != nil {
				t.Fatal(err)
			}
			reload(t, e)

			rr := httptest.NewRecorder()
			e.serveHTTPS(rr, h3Request(method, "h3.test", "/"))

			mu.Lock()
			te := gotTE
			mu.Unlock()
			if len(te) > 0 {
				t.Errorf("upstream saw Transfer-Encoding %v, want none (strict backends 400 a chunked GET)", te)
			}
			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rr.Code)
			}
		})
	}
}

// TestBodyfulRequestStillStreams guards the other side of the fix: an
// unknown-length POST must still reach the upstream intact.
func TestBodyfulRequestStillStreams(t *testing.T) {
	var mu sync.Mutex
	var gotBody string
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = string(b)
		mu.Unlock()
	})

	e, st := newTestEngine(t)
	if err := st.CreateHost(&store.Host{
		Type: "proxy", Domains: []string{"body.test"}, CertMode: "none", Enabled: true,
		Upstream: up,
	}); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	r := httptest.NewRequest(http.MethodPost, "http://body.test/", strings.NewReader("payload-123"))
	r.Host = "body.test"
	r.RemoteAddr = "10.0.0.5:50000"
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/3.0", 3, 0
	r.ContentLength = -1 // unknown length, as h3 streaming uploads report
	e.serveHTTPS(httptest.NewRecorder(), r)

	mu.Lock()
	defer mu.Unlock()
	if gotBody != "payload-123" {
		t.Errorf("upstream body = %q, want %q (unknown-length uploads must not be dropped)", gotBody, "payload-123")
	}
}

// TestBodylessThroughLocation covers the same normalization on the per-location
// proxy path, which builds its own Rewrite.
func TestBodylessThroughLocation(t *testing.T) {
	var mu sync.Mutex
	var gotTE []string
	locUp := backend(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotTE = r.TransferEncoding
		mu.Unlock()
		if len(r.TransferEncoding) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "loc")
	})
	defUp := backend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "default")
	})

	e, st := newTestEngine(t)
	if err := st.CreateHost(&store.Host{
		Type: "proxy", Domains: []string{"loc.test"}, CertMode: "none", Enabled: true,
		Upstream:  defUp,
		Locations: []store.Location{{Path: "/api", Upstream: locUp}},
	}); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	rr := httptest.NewRecorder()
	e.serveHTTPS(rr, h3Request(http.MethodGet, "loc.test", "/api/thing"))

	mu.Lock()
	defer mu.Unlock()
	if len(gotTE) > 0 {
		t.Errorf("location upstream saw Transfer-Encoding %v, want none", gotTE)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
