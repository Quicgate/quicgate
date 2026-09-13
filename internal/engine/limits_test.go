package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// Q14: per-host metrics are labelled by configured routes only, so a client
// cannot grow the metrics state (and output) by inventing Host headers.
func TestMetricsHostCardinalityIsBounded(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"known.test"}, Upstream: up})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"*.wild.test"}, Upstream: up})
	reload(t, e)

	h := e.accessLog.wrap(e.serveHTTPS)
	send := func(host string) {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.9:1"
		h(httptest.NewRecorder(), r)
	}
	for i := 0; i < 1001; i++ {
		send(fmt.Sprintf("scanner-%d.example", i))
		send(fmt.Sprintf("case%d.KNOWN.test", i)) // unknown subdomain of a known name
	}
	for _, v := range []string{"known.test", "KNOWN.test", "known.test.", "known.test:443", "a.wild.test", "B.WILD.test"} {
		send(v)
	}

	labels := map[string]bool{}
	for _, line := range strings.Split(e.MetricsText(), "\n") {
		if strings.HasPrefix(line, "quicgate_host_requests_total{") {
			labels[line[strings.Index(line, "{"):strings.Index(line, "}")+1]] = true
		}
	}
	if len(labels) > 3 {
		t.Fatalf("metrics carry %d host labels after 2000 invented Host headers, want at most 3 (known, wildcard, unmatched): %v", len(labels), labels)
	}
	// Bounded must not mean useless: configured routes keep their own label.
	for _, want := range []string{`{host="known.test"}`, `{host="*.wild.test"}`, `{host="_unmatched"}`} {
		if !labels[want] {
			t.Fatalf("metrics labels %v are missing %s", labels, want)
		}
	}
}

// Q14: the rate limit bounds work before authentication, so repeated guesses
// at basic-auth credentials are throttled rather than each costing a bcrypt
// comparison.
func TestRateLimitAppliesBeforeAuthentication(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "users", Satisfy: "all",
		Users: []store.AccessUser{{Username: "u", Password: "right"}}})
	h := &store.Host{Type: "proxy", Domains: []string{"rl.test"}, Upstream: up, AccessListID: &aclID}
	h.Options.RateLimit = &store.RateLimit{RPS: 0.01, Burst: 1}
	mustCreateHost(t, st, h)
	reload(t, e)

	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, req(e, "GET", "rl.test", "/", "203.0.113.9", map[string]string{"Authorization": basic("u", "wrong")}).Code)
	}
	if codes[1] != http.StatusTooManyRequests || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("wrong-password attempts got %v, want the rate limit (429) from the second attempt on", codes)
	}
}
