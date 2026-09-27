package store

import (
	"strings"
	"testing"
)

func validProxyHost() *Host {
	return &Host{Type: "proxy", Domains: []string{"v.test"}, CertMode: "none", Enabled: true,
		Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}
}

// Every field a host is dialled, served or shaped by has bounds: DNS name
// sizes, hosts that are hosts and nothing more, an absolute static root, an
// http(s) forward-auth URL, header names that are tokens and never the
// connection's own, and ceilings on the numbers. Each one backs a server-side
// refusal, so a pasted value or a stray zero cannot save a host the engine
// then does something odd with.
func TestHostValidationBounds(t *testing.T) {
	ok := func(name string, change func(h *Host)) {
		h := validProxyHost()
		change(h)
		if err := h.Validate(); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	bad := func(name, reason string, change func(h *Host)) {
		h := validProxyHost()
		change(h)
		err := h.Validate()
		if err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: got %v, want an error mentioning %q", name, err, reason)
		}
	}

	label63, label64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	ok("label of 63", func(h *Host) { h.Domains = []string{label63 + ".test"} })
	bad("label of 64", "too long", func(h *Host) { h.Domains = []string{label64 + ".test"} })
	bad("name past 253", "too long", func(h *Host) {
		h.Domains = []string{strings.Repeat(strings.Repeat("b", 50)+".", 5) + "test"}
	})
	bad("wildcard label of 64", "too long", func(h *Host) { h.Domains = []string{"*." + label64 + ".test"} })

	ok("upstream by IPv6", func(h *Host) { h.Upstream.Host = "fd00::10" })
	ok("upstream with an underscore", func(h *Host) { h.Upstream.Host = "svc_backend" })
	bad("upstream with a scheme", "upstream host", func(h *Host) { h.Upstream.Host = "http://backend" })
	bad("upstream with a port", "upstream host", func(h *Host) { h.Upstream.Host = "10.0.0.1:80" })
	bad("upstream with a space", "upstream host", func(h *Host) { h.Upstream.Host = "back end" })
	bad("pool upstream with a path", "upstream host", func(h *Host) {
		h.Upstreams = []Upstream{{Scheme: "http", Host: "backend/api", Port: 80}}
	})

	ok("static root absolute", func(h *Host) { h.Type = "static"; h.StaticRoot = "/srv/www/site/" })
	bad("static root relative", "absolute", func(h *Host) { h.Type = "static"; h.StaticRoot = "www" })
	h := validProxyHost()
	h.Type, h.StaticRoot = "static", "/srv/www/../www/site/"
	if err := h.Validate(); err != nil || h.StaticRoot != "/srv/www/site" {
		t.Errorf("static root not cleaned: %q %v", h.StaticRoot, err)
	}

	ok("redirect target with a port", func(h *Host) {
		h.Type, h.Redirect = "redirect", &Redirect{TargetHost: "new.test:8443"}
	})
	bad("redirect target with a scheme", "redirect target", func(h *Host) {
		h.Type, h.Redirect = "redirect", &Redirect{TargetHost: "https://new.test"}
	})
	bad("redirect target with a path", "redirect target", func(h *Host) {
		h.Type, h.Redirect = "redirect", &Redirect{TargetHost: "new.test/welcome"}
	})

	ok("forward auth https", func(h *Host) { h.Options.ForwardAuth = &ForwardAuth{URL: "https://auth.example.com/api/verify"} })
	bad("forward auth ftp", "forwardAuth.url", func(h *Host) { h.Options.ForwardAuth = &ForwardAuth{URL: "ftp://auth.example.com/verify"} })
	bad("forward auth without scheme", "forwardAuth.url", func(h *Host) { h.Options.ForwardAuth = &ForwardAuth{URL: "auth.example.com/verify"} })
	bad("forward auth without host", "forwardAuth.url", func(h *Host) { h.Options.ForwardAuth = &ForwardAuth{URL: "http:///verify"} })

	ok("header X-Custom", func(h *Host) {
		h.Options.RequestHeaders = []HeaderRule{{Op: "set", Name: "X-Custom", Value: "1"}}
		h.Options.ResponseHeaders = []HeaderRule{{Op: "remove", Name: "Server"}}
	})
	bad("header name with a space", "not a valid header name", func(h *Host) {
		h.Options.RequestHeaders = []HeaderRule{{Op: "set", Name: "X Custom", Value: "1"}}
	})
	bad("header name with a colon", "not a valid header name", func(h *Host) {
		h.Options.ResponseHeaders = []HeaderRule{{Op: "set", Name: "X-Custom:", Value: "1"}}
	})
	for _, name := range []string{"Host", "content-length", "Transfer-Encoding", "Connection", "Upgrade", "Keep-Alive", "TE", "Trailer"} {
		bad("request header rule on "+name, "cannot be changed by a rule", func(h *Host) {
			h.Options.RequestHeaders = []HeaderRule{{Op: "set", Name: name, Value: "x"}}
		})
		bad("response header rule on "+name, "cannot be changed by a rule", func(h *Host) {
			h.Options.ResponseHeaders = []HeaderRule{{Op: "remove", Name: name}}
		})
	}

	ok("dialTimeoutSec at the ceiling", func(h *Host) { h.Options.DialTimeoutSec = 3600 })
	bad("dialTimeoutSec past an hour", "dialTimeoutSec", func(h *Host) { h.Options.DialTimeoutSec = 3601 })
	bad("responseHeaderTimeoutSec past an hour", "responseHeaderTimeoutSec", func(h *Host) { h.Options.ResponseHeaderTimeoutSec = 3601 })
	bad("idleTimeoutSec past an hour", "idleTimeoutSec", func(h *Host) { h.Options.IdleTimeoutSec = 3601 })
	bad("cacheSec past a month", "cacheSec", func(h *Host) { h.Options.CacheSec = 30*24*3600 + 1 })
	bad("maxBodyMb past 10 GiB", "maxBodyMb", func(h *Host) { h.Options.MaxBodyMB = 10241 })
	bad("negative cacheSec", "negative", func(h *Host) { h.Options.CacheSec = -1 })
	ok("hsts two years", func(h *Host) { h.Options.HSTS = HSTS{Enabled: true, MaxAge: 63072000} })
	bad("hsts past two years", "hsts.maxAge", func(h *Host) { h.Options.HSTS = HSTS{Enabled: true, MaxAge: 63072001} })
}

// Streams: a forward port of 0 is only meaningful for a port range (each port
// to its own number) or a stream that is nothing but SNI routes; a range's
// last forward port must exist; hosts are hosts; SNI routes have the same
// port bounds as everything else.
func TestStreamValidationBounds(t *testing.T) {
	mk := func() *Stream {
		return &Stream{ListenPort: 4000, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 22, Enabled: true}
	}
	check := func(name, reason string, s *Stream) {
		err := s.Validate(nil, nil)
		switch {
		case reason == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case reason != "" && (err == nil || !strings.Contains(err.Error(), reason)):
			t.Errorf("%s: got %v, want an error mentioning %q", name, err, reason)
		}
	}
	s := mk()
	s.ForwardPort = 0
	check("forward port 0 on a single port", "forward port is required", s)
	s = mk()
	s.ForwardPort = 70000
	check("forward port past 65535", "out of range", s)
	s = mk()
	s.ListenPortEnd, s.ForwardPort = 4010, 0
	check("range forwarding to the same numbers", "", s)
	s = mk()
	s.ListenPortEnd, s.ForwardPort = 4010, 65530
	check("range running past 65535", "goes past 65535", s)
	s = mk()
	s.ForwardHost = "back end"
	check("forward host with a space", "forward host", s)
	s = mk()
	s.ForwardHost = "10.0.0.2:22"
	check("forward host with a port", "forward host", s)
	s = mk()
	s.ForwardHost, s.ForwardPort = "", 0
	s.SNIRoutes = []SNIRoute{{Host: "a.test", ForwardHost: "10.0.0.2", ForwardPort: 443}}
	check("SNI routes without a default backend", "", s)
	s = mk()
	s.SNIRoutes = []SNIRoute{{Host: "a.test", ForwardHost: "10.0.0.2", ForwardPort: 70000}}
	check("SNI route forward port past 65535", "SNI route 1: forward port", s)
	s = mk()
	s.SNIRoutes = []SNIRoute{{Host: "a.test", ForwardHost: "10.0.0.2:443", ForwardPort: 443}}
	check("SNI route forward host with a port", "SNI route 1: forward host", s)
}

func TestSelfSignedValidityIsBounded(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.GenerateSelfSigned("long", []string{"long.test"}, 3651); err == nil || !strings.Contains(err.Error(), "3650") {
		t.Fatalf("3651 days: %v", err)
	}
	if _, err := st.GenerateSelfSigned("ten-years", []string{"ten.test"}, 3650); err != nil {
		t.Fatalf("3650 days: %v", err)
	}
}
