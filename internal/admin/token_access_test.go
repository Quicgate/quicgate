package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// bearer makes one API call with a token.
func bearer(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func mustToken(t *testing.T, s *Server, access string) string {
	t.Helper()
	tok, err := s.store.CreateAPITokenFor("test "+access, access)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

// secretHost is a proxy host whose configuration holds something a status
// page must never show: the credentials quicgate sends to its backend.
func secretHost(t *testing.T, s *Server, domain string) store.Host {
	t.Helper()
	h := store.Host{
		Type: "proxy", Domains: []string{domain}, CertMode: "none", Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080},
		Options: store.Options{RequestHeaders: []store.HeaderRule{
			{Op: "set", Name: "Authorization", Value: "Bearer backend-s3cret"},
		}},
	}
	if err := s.store.CreateHost(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

// everythingElse is what a limited token must be refused: reads that carry
// configuration, secrets or logs, and every write.
var everythingElse = []struct{ method, path string }{
	{http.MethodGet, "/api/hosts"},
	{http.MethodGet, "/api/settings"},
	{http.MethodGet, "/api/backup"},
	{http.MethodGet, "/api/tokens"},
	{http.MethodGet, "/api/logs"},
	{http.MethodGet, "/api/access-lists"},
	{http.MethodGet, "/api/custom-certs"},
	{http.MethodGet, "/api/oidc-providers"},
	{http.MethodGet, "/api/streams"},
	{http.MethodGet, "/api/config"},
	{http.MethodGet, "/api/wg/status"},
	{http.MethodGet, "/api/wg/devices"},
	{http.MethodGet, "/api/docker/status"},
	{http.MethodPost, "/api/tokens"},
	{http.MethodPost, "/api/hosts"},
	{http.MethodPut, "/api/hosts/1"},
	{http.MethodDelete, "/api/hosts/1"},
	{http.MethodPut, "/api/settings"},
	{http.MethodPost, "/api/restore"},
	{http.MethodPost, "/api/import"},
	{http.MethodDelete, "/api/bans/203.0.113.5"},
	{http.MethodDelete, "/api/tokens/1"},
	{http.MethodPost, "/api/password"},
	{http.MethodPost, "/api/logout"},
	{http.MethodPost, "/api/geoip/reload"},
	{http.MethodPut, "/api/wg/devices/1/enabled"},
	{http.MethodGet, "/api/wg/devices/1/flows"},
	{http.MethodPut, "/api/wg/devices/1/access"},
}

// A monitoring token reads status and nothing else: not a host's
// configuration, not settings, logs or backups, and it changes nothing.
func TestMonitoringTokenReadsStatusAndNothingElse(t *testing.T) {
	s := newTestServer(t)
	h := secretHost(t, s, "app.example.com")
	tok := mustToken(t, s, store.TokenMonitor)

	for _, path := range []string{"/api/me", "/api/overview", "/api/hosts/status", "/api/health", "/api/certs", "/api/traffic", "/api/bans", "/metrics"} {
		if rr := bearer(t, s, http.MethodGet, path, tok, nil); rr.Code != http.StatusOK {
			t.Errorf("GET %s with a monitoring token: %d %s, want 200", path, rr.Code, rr.Body.String())
		}
	}
	for _, c := range everythingElse {
		if rr := bearer(t, s, c.method, c.path, tok, map[string]any{}); rr.Code != http.StatusForbidden {
			t.Errorf("%s %s with a monitoring token: %d, want 403", c.method, c.path, rr.Code)
		}
	}
	if rr := bearer(t, s, http.MethodPut, "/api/hosts/1/enabled", tok, map[string]bool{"enabled": false}); rr.Code != http.StatusForbidden {
		t.Errorf("a monitoring token switched a host: %d, want 403", rr.Code)
	}
	if got, _ := s.store.GetHost(h.ID); !got.Enabled {
		t.Error("the host is off after a monitoring token tried to switch it")
	}
	// A path that only looks like an allowed one is not served.
	if rr := bearer(t, s, http.MethodGet, "/api/hosts/status/../../settings", tok, nil); rr.Code == http.StatusOK {
		t.Errorf("a dressed-up path reached settings with a monitoring token: %d %s", rr.Code, rr.Body.String())
	}
}

// The API reference is for people who are signed in and for full tokens.
func TestLimitedTokenDoesNotReadTheAPIReference(t *testing.T) {
	s := newStaticTestServer(t)
	for _, access := range []string{store.TokenMonitor, store.TokenSwitch} {
		if rr := bearer(t, s, http.MethodGet, "/openapi.yaml", mustToken(t, s, access), nil); rr.Code != http.StatusForbidden {
			t.Errorf("GET /openapi.yaml with a %s token: %d, want 403", access, rr.Code)
		}
	}
	if rr := bearer(t, s, http.MethodGet, "/openapi.yaml", mustToken(t, s, store.TokenFull), nil); rr.Code != http.StatusOK {
		t.Errorf("GET /openapi.yaml with a full token: %d, want 200", rr.Code)
	}
}

// A switch token does what a monitoring token does, and switches a host on or
// off. Switching changes that one thing about the host.
func TestSwitchTokenSwitchesAHostAndNothingElse(t *testing.T) {
	s := newTestServer(t)
	h := secretHost(t, s, "app.example.com")
	tok := mustToken(t, s, store.TokenSwitch)

	if rr := bearer(t, s, http.MethodGet, "/api/hosts/status", tok, nil); rr.Code != http.StatusOK {
		t.Fatalf("GET /api/hosts/status with a switch token: %d", rr.Code)
	}
	for _, c := range everythingElse {
		if rr := bearer(t, s, c.method, c.path, tok, map[string]any{}); rr.Code != http.StatusForbidden {
			t.Errorf("%s %s with a switch token: %d, want 403", c.method, c.path, rr.Code)
		}
	}

	before, _ := s.store.GetHost(h.ID)
	path := "/api/hosts/" + itoa(h.ID) + "/enabled"
	if rr := bearer(t, s, http.MethodPut, path, tok, map[string]bool{"enabled": false}); rr.Code != http.StatusOK {
		t.Fatalf("switching a host off: %d %s", rr.Code, rr.Body.String())
	}
	after, _ := s.store.GetHost(h.ID)
	if after.Enabled {
		t.Fatal("the host is still on")
	}
	before.Enabled, before.UpdatedAt, after.UpdatedAt = false, "", ""
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Errorf("switching a host off changed more than that:\n before %s\n after  %s", a, b)
	}
	if rr := bearer(t, s, http.MethodPut, path, tok, map[string]bool{"enabled": true}); rr.Code != http.StatusOK {
		t.Fatalf("switching a host on: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetHost(h.ID); !got.Enabled {
		t.Fatal("the host is still off")
	}

	if rr := bearer(t, s, http.MethodPut, "/api/hosts/999/enabled", tok, map[string]bool{"enabled": true}); rr.Code != http.StatusNotFound {
		t.Errorf("switching a host that does not exist: %d, want 404", rr.Code)
	}
	if rr := bearer(t, s, http.MethodPut, path, tok, map[string]any{}); rr.Code != http.StatusBadRequest {
		t.Errorf("a switch that does not say on or off: %d, want 400", rr.Code)
	}
	// The switch is not a back door to the rest of a host.
	if rr := bearer(t, s, http.MethodPut, path, tok, map[string]any{"enabled": true, "domains": []string{"evil.example.com"}}); rr.Code != http.StatusBadRequest {
		t.Errorf("a switch that also carries other fields: %d, want 400", rr.Code)
	}
	if got, _ := s.store.GetHost(h.ID); len(got.Domains) != 1 || got.Domains[0] != "app.example.com" {
		t.Errorf("the host's names changed: %v", got.Domains)
	}
}

// The host status says what a host is and how it is doing, and nothing about
// how it is configured.
func TestHostStatusLeavesConfigurationOut(t *testing.T) {
	s := newTestServer(t)
	secretHost(t, s, "app.example.com")
	off := secretHost(t, s, "old.example.com")
	if err := s.store.SetHostEnabled(off.ID, false); err != nil {
		t.Fatal(err)
	}
	rr := bearer(t, s, http.MethodGet, "/api/hosts/status", mustToken(t, s, store.TokenMonitor), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/hosts/status: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, leak := range []string{"backend-s3cret", "requestHeaders", "options", "Authorization"} {
		if strings.Contains(body, leak) {
			t.Errorf("the host status carries %q: %s", leak, body)
		}
	}
	var got []struct {
		ID      int64
		Name    string
		Type    string
		Enabled bool
		Target  string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d hosts in the status, want 2: %s", len(got), body)
	}
	if got[0].Name != "app.example.com" || !got[0].Enabled || got[0].Type != "proxy" || got[0].Target != "http://10.0.0.5:8080" {
		t.Errorf("first host reads %+v", got[0])
	}
	if got[1].Name != "old.example.com" || got[1].Enabled {
		t.Errorf("the host that is off reads %+v", got[1])
	}
}

// A full token still does everything, the API says what a token may do, and
// a token is made full unless asked otherwise.
func TestTokenAccessIsChosenAtCreation(t *testing.T) {
	s := newTestServer(t)
	full := mustToken(t, s, store.TokenFull)

	create := func(body map[string]string) (int, store.APIToken) {
		rr := bearer(t, s, http.MethodPost, "/api/tokens", full, body)
		var tok store.APIToken
		_ = json.Unmarshal(rr.Body.Bytes(), &tok)
		return rr.Code, tok
	}
	if code, tok := create(map[string]string{"name": "old script"}); code != http.StatusCreated || tok.Access != store.TokenFull || !strings.HasPrefix(tok.Token, "qg_") {
		t.Errorf("a token made without saying what it may do: %d %+v, want a full one", code, tok)
	}
	code, mon := create(map[string]string{"name": "dashboard", "access": "monitor"})
	if code != http.StatusCreated || mon.Access != store.TokenMonitor || !strings.HasPrefix(mon.Token, "qgm_") {
		t.Errorf("a monitoring token: %d %+v", code, mon)
	}
	if code, tok := create(map[string]string{"name": "switches", "access": "switch"}); code != http.StatusCreated || tok.Access != store.TokenSwitch || !strings.HasPrefix(tok.Token, "qgs_") {
		t.Errorf("a switch token: %d %+v", code, tok)
	}
	if code, _ := create(map[string]string{"name": "typo", "access": "admin"}); code != http.StatusBadRequest {
		t.Errorf("a token with a made-up access level: %d, want 400", code)
	}

	var me struct {
		Token  bool
		Access string
	}
	rr := bearer(t, s, http.MethodGet, "/api/me", mon.Token, nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil || !me.Token || me.Access != store.TokenMonitor {
		t.Errorf("/api/me for a monitoring token: %s", rr.Body.String())
	}
	rr = bearer(t, s, http.MethodGet, "/api/tokens", full, nil)
	if !strings.Contains(rr.Body.String(), `"access":"monitor"`) || !strings.Contains(rr.Body.String(), `"access":"switch"`) {
		t.Errorf("the token list does not say what each token may do: %s", rr.Body.String())
	}
	if rr := bearer(t, s, http.MethodGet, "/api/settings", full, nil); rr.Code != http.StatusOK {
		t.Errorf("a full token reading settings: %d, want 200", rr.Code)
	}
}

// An access level nobody defined may do nothing.
func TestUnknownTokenAccessMayDoNothing(t *testing.T) {
	for _, pattern := range []string{"GET /api/me", "GET /api/hosts/status", "PUT /api/hosts/{id}/enabled", "GET /api/settings"} {
		if tokenMay("", pattern) || tokenMay("admin", pattern) {
			t.Errorf("an unknown access level may call %s", pattern)
		}
	}
	if tokenMay(store.TokenMonitor, "") || tokenMay(store.TokenSwitch, "") {
		t.Error("a limited token may call a request that matched no route")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
