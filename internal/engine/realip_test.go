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

// A front proxy that appends the client as a header line of its own (HAProxy's
// option forwardfor, any Go proxy using Header.Add) must not let the client
// pick its address with a first line it wrote itself: every line is part of
// the walk, and the address the nearest proxy added is still where it starts.
func TestRealClientIPReadsEveryHeaderLine(t *testing.T) {
	cfg := mkRealIP("X-Forwarded-For", "127.0.0.0/8")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Add("X-Forwarded-For", "10.1.1.1")    // written by the client
	r.Header.Add("X-Forwarded-For", "203.0.113.9") // added by the front proxy
	if got := cfg.realClientIP(r); got != "203.0.113.9" {
		t.Fatalf("two header lines: got %q, want the address the proxy added", got)
	}
	// A trusted hop on a line of its own is skipped like one in the same line.
	r.Header.Add("X-Forwarded-For", "127.0.0.2")
	if got := cfg.realClientIP(r); got != "203.0.113.9" {
		t.Fatalf("trusted hop on its own line: got %q, want 203.0.113.9", got)
	}
}
