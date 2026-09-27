package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The trusted-proxy list is validated as a whole (M-20): an entry that is not
// an address or a range, or a range that covers everything, is refused.
func TestParseTrustedProxies(t *testing.T) {
	good, err := parseTrustedProxies("10.0.0.0/8, 192.0.2.1\n2001:db8::/32 ::1")
	if err != nil || len(good) != 4 || good[1].String() != "192.0.2.1/32" || good[3].String() != "::1/128" {
		t.Fatalf("valid list: %v %v", good, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8, bogus", "10.0.0.0/33", "192.0.2.1:80", "10.0.0.0 / 8", "192.168.1"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if list, err := parseTrustedProxies(" \n"); err != nil || len(list) != 0 {
		t.Errorf("an empty list: %v %v", list, err)
	}
	for name, ok := range map[string]bool{
		"X-Forwarded-For": true, "CF-Connecting-IP": true, "x_real_ip": true,
		"": false, "X Forwarded": false, "X-Forwarded-For:": false, "\xc3\xbcber": false,
	} {
		if got := validHeaderName(name); got != ok {
			t.Errorf("validHeaderName(%q) = %v, want %v", name, got, ok)
		}
	}
}

// The client address is read from the header only behind a trusted proxy, over
// every header line, from the right, past trusted hops (M-3).
func TestClientIPWalksEveryHeaderLineFromTheRight(t *testing.T) {
	nets, err := parseTrustedProxies("127.0.0.1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &clientIPConfig{nets: nets, header: "X-Forwarded-For"}
	req := func(peer string, lines ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		for _, l := range lines {
			r.Header.Add("X-Forwarded-For", l)
		}
		return r
	}
	for _, c := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"untrusted peer: the header is ignored", req("198.51.100.7:1", "203.0.113.9"), "198.51.100.7"},
		{"trusted peer, no header", req("127.0.0.1:1"), "127.0.0.1"},
		{"one line", req("127.0.0.1:1", "203.0.113.9"), "203.0.113.9"},
		{"a client's spoof left of the real address", req("127.0.0.1:1", "203.0.113.9, 198.51.100.7"), "198.51.100.7"},
		{"a trusted hop is skipped", req("127.0.0.1:1", "198.51.100.7, 10.1.2.3"), "198.51.100.7"},
		{"the line the proxy added counts", req("127.0.0.1:1", "203.0.113.9", "198.51.100.7"), "198.51.100.7"},
		{"an address with a port", req("127.0.0.1:1", "[2001:db8::9]:443"), "2001:db8::9"},
		{"garbage nearest the proxy ends the walk at the peer", req("127.0.0.1:1", "203.0.113.9, unknown"), "127.0.0.1"},
		{"every hop trusted: the first one", req("127.0.0.1:1", "10.9.9.9, 10.1.2.3"), "10.9.9.9"},
		{"a mapped v4 address", req("127.0.0.1:1", "::ffff:198.51.100.7"), "198.51.100.7"},
	} {
		if got := cfg.clientIP(c.r); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Without a configuration, or without a header name, the socket peer.
	if got := (*clientIPConfig)(nil).clientIP(req("127.0.0.1:1", "203.0.113.9")); got != "127.0.0.1" {
		t.Errorf("no configuration: %q", got)
	}
	if got := (&clientIPConfig{nets: nets}).clientIP(req("127.0.0.1:1", "203.0.113.9")); got != "127.0.0.1" {
		t.Errorf("no header name: %q", got)
	}
}

// In the documented deployment the admin UI sits behind quicgate itself, so
// every login arrives from 127.0.0.1: without the trusted-proxy settings one
// attacker's ten failures would lock every administrator out (M-3). With them,
// the throttle keys on the client the proxy names, and a saved change applies
// without a restart.
func TestLoginThrottleHonoursTrustedProxies(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	mustUser(t, s, "other@example.com", "password-456")
	sess := login(t, s, "admin@example.com", "password-123")
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"trusted_proxies": "127.0.0.1", "real_ip_header": "X-Forwarded-For"}); rr.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rr.Code, rr.Body.String())
	}
	attempt := func(peer, email, pw string, xff ...string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"Email": email, "Password": pw})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		r.RemoteAddr = peer + ":4000"
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, r)
		return rr.Code
	}
	for i := 0; i < loginMaxFails; i++ {
		if code := attempt("127.0.0.1", "admin@example.com", "wrong", "203.0.113.9"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i+1, code)
		}
	}
	// The client behind the proxy is locked out ...
	if code := attempt("127.0.0.1", "other@example.com", "password-456", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("the locked client behind the proxy: %d, want 429", code)
	}
	// ... another client behind the same proxy is not.
	if code := attempt("127.0.0.1", "other@example.com", "password-456", "198.51.100.7"); code != http.StatusOK {
		t.Fatalf("another client behind the proxy: %d, want 200", code)
	}
	// The line the proxy added is what counts, not the client's own.
	if code := attempt("127.0.0.1", "other@example.com", "password-456", "198.51.100.7", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("the locked client with a spoofed first line: %d, want 429", code)
	}
	// From a peer that is not a trusted proxy the header means nothing.
	if code := attempt("198.51.100.99", "other@example.com", "password-456", "203.0.113.9"); code != http.StatusOK {
		t.Fatalf("an untrusted peer naming the locked client: %d, want 200", code)
	}
}

// Trusted-proxy settings are validated on save (M-20).
func TestSettingsValidateTrustedProxySettings(t *testing.T) {
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	for name, bad := range map[string]map[string]string{
		"every address":      {"trusted_proxies": "0.0.0.0/0"},
		"every v6 address":   {"trusted_proxies": "::/0"},
		"a typo":             {"trusted_proxies": "10.0.0.0/8, 192.168.1"},
		"not a header name":  {"real_ip_header": "X Forwarded For"},
		"a header with junk": {"real_ip_header": "X-Forwarded-For: 1.2.3.4"},
	} {
		if rr := call(t, s, http.MethodPut, "/api/settings", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s %v: %d %s, want 400", name, bad, rr.Code, rr.Body.String())
		}
	}
	if got := s.store.GetSetting("trusted_proxies", "unset"); got != "unset" {
		t.Fatalf("a refused list was stored: %q", got)
	}
	if got := s.store.GetSetting("real_ip_header", "unset"); got != "unset" {
		t.Fatalf("a refused header name was stored: %q", got)
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"trusted_proxies": "10.0.0.0/8\n192.0.2.1", "real_ip_header": " X-Forwarded-For "}); rr.Code != http.StatusOK {
		t.Fatalf("a valid configuration: %d %s", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("real_ip_header", ""); got != "X-Forwarded-For" {
		t.Fatalf("stored header name = %q, want it trimmed", got)
	}
	if cfg := s.clientIPCfg.Load(); cfg == nil || len(cfg.nets) != 2 || cfg.header != "X-Forwarded-For" {
		t.Fatalf("the admin listener did not pick the settings up: %+v", cfg)
	}
}
