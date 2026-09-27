package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// A custom location is a path decision like a path rule: its prefix matches
// whole segments, and the paths an upstream may read differently from the
// text compare are refused before any location is chosen.
func TestLocationsMatchWholeSegmentsAndRefuseAmbiguousPaths(t *testing.T) {
	e, st := newTestEngine(t)
	def := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("default")) })
	api := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("location")) })
	h := &store.Host{Type: "proxy", Domains: []string{"loc.test"}, Upstream: def,
		Locations: []store.Location{{Path: "/api", Upstream: api}}}
	mustCreateHost(t, st, h)
	reload(t, e)

	for _, c := range []struct {
		path string
		code int
		body string
	}{
		{"/api", http.StatusOK, "location"},
		{"/api/users", http.StatusOK, "location"},
		{"/api-internal/keys", http.StatusOK, "default"},
		{"/apix", http.StatusOK, "default"},
		{"/other", http.StatusOK, "default"},
		{"//api/users", http.StatusBadRequest, ""},
		{"/api;x/users", http.StatusBadRequest, ""},
		{"/other/..;/api/users", http.StatusBadRequest, ""},
		{"/other/%5c..%5capi/users", http.StatusBadRequest, ""},
	} {
		rr := req(e, "GET", "loc.test", c.path, "203.0.113.9", nil)
		if rr.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.path, rr.Code, c.code)
			continue
		}
		if c.body != "" && rr.Body.String() != c.body {
			t.Errorf("%s: served by %q, want %q", c.path, rr.Body.String(), c.body)
		}
	}
}
