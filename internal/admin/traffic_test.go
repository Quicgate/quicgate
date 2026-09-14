package admin

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The traffic history is behind admin authentication, validates its range and
// answers with one point per step, null where there is no data yet.
func TestTrafficEndpoint(t *testing.T) {
	s := newTestServer(t)
	if rr := call(t, s, http.MethodGet, "/api/traffic", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/traffic: %d, want 401", rr.Code)
	}
	mustUser(t, s, "ops@example.com", "correct horse battery staple")
	sess := login(t, s, "ops@example.com", "correct horse battery staple")
	if rr := call(t, s, http.MethodGet, "/api/traffic?range=1y", sess, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown range: %d, want 400", rr.Code)
	}

	for rng, want := range map[string]struct {
		step   int64
		points int
	}{"": {10, 360}, "1h": {10, 360}, "6h": {300, 72}, "24h": {300, 288}, "7d": {3600, 168}} {
		rr := call(t, s, http.MethodGet, "/api/traffic?range="+rng, sess, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("range %q: %d %s", rng, rr.Code, rr.Body.String())
		}
		var rep struct {
			Step   int64 `json:"step"`
			Series struct {
				In []*float64 `json:"in"`
			} `json:"series"`
			Totals struct {
				Blocked map[string]uint64 `json:"blocked"`
			} `json:"totals"`
			Ports []json.RawMessage `json:"ports"`
			Hosts []json.RawMessage `json:"hosts"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
			t.Fatalf("range %q: %v", rng, err)
		}
		if rep.Step != want.step || len(rep.Series.In) != want.points {
			t.Fatalf("range %q: step %d with %d points, want %d with %d", rng, rep.Step, len(rep.Series.In), want.step, want.points)
		}
		for i, v := range rep.Series.In {
			if v != nil {
				t.Fatalf("range %q: point %d = %v on a fresh engine, want null", rng, i, *v)
			}
		}
		if rep.Ports == nil || rep.Hosts == nil || len(rep.Totals.Blocked) == 0 {
			t.Fatalf("range %q: ports %v, hosts %v, blocked %v; want empty lists and every reason", rng, rep.Ports, rep.Hosts, rep.Totals.Blocked)
		}
	}
}
