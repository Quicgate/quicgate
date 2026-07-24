package engine

import (
	"net"
	"net/http"
	"testing"
)

func mkRealIP(header string, cidrs ...string) *realIPConfig {
	c := &realIPConfig{header: header}
	for _, s := range cidrs {
		if _, n, err := net.ParseCIDR(s); err == nil {
			c.nets = append(c.nets, n)
		}
	}
	return c
}

func TestRealClientIP(t *testing.T) {
	cfg := mkRealIP("X-Forwarded-For", "10.0.0.0/8")
	req := func(remote, xff string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"trusted peer, real client", "10.1.2.3:5000", "203.0.113.9", "203.0.113.9"},
		{"rightmost-untrusted defeats spoof", "10.1.2.3:5000", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"skip trusted proxy hops", "10.1.2.3:5000", "203.0.113.9, 10.0.0.1, 10.0.0.2", "203.0.113.9"},
		{"untrusted peer is ignored", "8.8.8.8:5000", "203.0.113.9", ""},
		{"trusted peer, no header", "10.1.2.3:5000", "", ""},
	}
	for _, c := range cases {
		if got := cfg.realClientIP(req(c.remote, c.xff)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
