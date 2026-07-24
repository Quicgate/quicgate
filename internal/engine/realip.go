package engine

import (
	"net"
	"net/http"
	"strings"
)

// realIPConfig is the compiled trusted-proxy configuration. When a request's
// immediate peer is one of the trusted proxies, the real client IP is read from
// the configured header instead of the socket address, so access lists, GeoIP,
// rate limiting and logging all see the true client.
type realIPConfig struct {
	nets   []*net.IPNet
	header string
}

func (c *realIPConfig) trusts(ip net.IP) bool {
	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// realClientIP returns the real client IP for a request, or "" to keep the
// socket address. It only trusts the header when the immediate peer is a
// trusted proxy, then walks the header right-to-left returning the first
// address that is not itself a trusted proxy, which defeats client spoofing of
// the header.
func (c *realIPConfig) realClientIP(r *http.Request) string {
	pip := net.ParseIP(hostOnly(r.RemoteAddr))
	if pip == nil || !c.trusts(pip) {
		return ""
	}
	vals := strings.Split(r.Header.Get(c.header), ",")
	for i := len(vals) - 1; i >= 0; i-- {
		if ip := net.ParseIP(strings.TrimSpace(vals[i])); ip != nil && !c.trusts(ip) {
			return ip.String()
		}
	}
	// Every hop was a trusted proxy (or a single trusted value): fall back to
	// the leftmost valid address in the header.
	for _, v := range vals {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// wrapRealIP rewrites r.RemoteAddr to the real client IP before any other
// middleware runs, so everything downstream uses the true client. It is a
// no-op unless trusted proxies and a header are configured.
func (e *Engine) wrapRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := e.realIP.Load(); c != nil && c.header != "" && len(c.nets) > 0 {
			if real := c.realClientIP(r); real != "" {
				r.RemoteAddr = net.JoinHostPort(real, "0")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// buildRealIP compiles the trusted-proxy settings into e.realIP. Called on
// every reload so a settings change applies without a restart.
func (e *Engine) buildRealIP() {
	raw := e.store.GetSetting("trusted_proxies", "")
	cfg := &realIPConfig{header: strings.TrimSpace(e.store.GetSetting("real_ip_header", ""))}
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r'
	}) {
		if !strings.Contains(tok, "/") {
			if strings.Contains(tok, ":") {
				tok += "/128"
			} else {
				tok += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(tok); err == nil {
			cfg.nets = append(cfg.nets, n)
		}
	}
	e.realIP.Store(cfg)
}
