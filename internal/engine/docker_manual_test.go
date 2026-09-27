package engine

import (
	"net/http"
	"testing"

	"quicgate/internal/store"
)

// "Manual hosts always win" also holds against the two holes of M-8: a
// container's exact name under a manual wildcard (lookup prefers the exact
// name, so the container would take *.wild.test's traffic for api.wild.test),
// and a manual host that is disabled (its name is configured; a container must
// not serve it in the meantime). The provider skips both before they reach the
// engine; this is the engine's own check, for routes that get past it.
func TestDockerRouteNeverTakesAConfiguredName(t *testing.T) {
	e, st := newTestEngine(t)
	manual := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("M")) })
	dockerUp := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("D")) })

	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"*.wild.test"}, Upstream: manual})
	off := &store.Host{Type: "proxy", Domains: []string{"off.test"}, Upstream: manual}
	mustCreateHost(t, st, off)
	off.Enabled = false
	if err := st.UpdateHost(off); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	e.SetDockerRoutes([]store.Host{
		{Type: "proxy", Domains: []string{"api.wild.test"}, Upstream: dockerUp, CertMode: "none", Enabled: true},
		{Type: "proxy", Domains: []string{"off.test"}, Upstream: dockerUp, CertMode: "none", Enabled: true},
		{Type: "proxy", Domains: []string{"free.test"}, Upstream: dockerUp, CertMode: "none", Enabled: true},
	}, nil)

	if rr := req(e, "GET", "api.wild.test", "/", "127.0.0.1", nil); rr.Body.String() != "M" {
		t.Fatalf("api.wild.test: body %q, want M (the manual wildcard host must win)", rr.Body.String())
	}
	if rr := req(e, "GET", "off.test", "/", "127.0.0.1", nil); rr.Code == http.StatusOK || rr.Body.String() == "D" {
		t.Fatalf("off.test: status %d body %q, want the disabled manual host's name left alone", rr.Code, rr.Body.String())
	}
	if rr := req(e, "GET", "free.test", "/", "127.0.0.1", nil); rr.Code != http.StatusOK || rr.Body.String() != "D" {
		t.Fatalf("free.test: status %d body %q, want 200 D", rr.Code, rr.Body.String())
	}
}
