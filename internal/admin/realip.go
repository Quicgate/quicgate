package admin

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// In the documented deployment the admin UI is proxied through quicgate itself
// (or another front proxy), so every request reaches this listener from the
// proxy's address. The login throttle keys on the client address, and with one
// shared address ten wrong passwords from anyone would lock every
// administrator out. The admin listener therefore honours the same
// trusted_proxies / real_ip_header settings as the data plane: only when the
// socket peer is a trusted proxy is the client read from the header, by a
// right-to-left walk over every header line that skips trusted hops. The
// settings are compiled at start and on every reload, so a change applies
// without a restart.

// clientIPConfig is the compiled trusted-proxy configuration.
type clientIPConfig struct {
	nets   []netip.Prefix
	header string
}

func (c *clientIPConfig) trusts(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseProxyToken parses one trusted-proxy entry: an address, or a CIDR range.
// A range that covers every address is refused, because it would let any host
// on the internet state any client address.
func parseProxyToken(tok string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(tok, "/") {
		var err error
		if p, err = netip.ParsePrefix(tok); err != nil {
			return p, errors.New(tok + " is not an address or a range like 10.0.0.0/8")
		}
	} else {
		a, err := netip.ParseAddr(tok)
		if err != nil {
			return p, errors.New(tok + " is not an address or a range like 10.0.0.0/8")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Bits() == 0 {
		return p, errors.New(tok + " would trust every address on the internet; list the proxies' own addresses")
	}
	return p.Masked(), nil
}

// splitProxyList splits a trusted-proxy setting on commas and whitespace.
func splitProxyList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}

// parseTrustedProxies parses a trusted-proxy setting and refuses it whole on
// the first entry that is not an address or a range. A typo that was dropped
// silently would make the front proxy untrusted, so every client became the
// proxy's address and one attacker's failures would lock everyone out.
func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, tok := range splitProxyList(raw) {
		p, err := parseProxyToken(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// validHeaderName reports whether s is an HTTP field name (an RFC 9110 token).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// loadClientIP compiles the stored trusted-proxy settings for this listener.
// A stored entry that does not parse (saved before entries were validated) is
// skipped and logged, never trusted.
func (s *Server) loadClientIP() {
	cfg := &clientIPConfig{header: strings.TrimSpace(s.store.GetSetting("real_ip_header", ""))}
	for _, tok := range splitProxyList(s.store.GetSetting("trusted_proxies", "")) {
		p, err := parseProxyToken(tok)
		if err != nil {
			log.Printf("admin: trusted_proxies: %v; the entry is ignored", err)
			continue
		}
		cfg.nets = append(cfg.nets, p)
	}
	s.clientIPCfg.Store(cfg)
}

// parseHop reads one address from a real-IP header list entry, with or
// without a port.
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// clientIP returns the client address of a request: the socket peer, unless
// that peer is a trusted proxy and the header names the client. Every line of
// the header is read (a proxy that adds a line of its own, as HAProxy and Go's
// Header.Add do, must not hide the line before it), and the walk runs from
// the right, past trusted hops, to the first address a trusted proxy saw as
// its peer. Anything left of that was written by the client and is not
// believed; an entry there that is not an address at all ends the walk at the
// socket peer.
func (c *clientIPConfig) clientIP(r *http.Request) string {
	peer := socketIP(r.RemoteAddr)
	if c == nil || c.header == "" || len(c.nets) == 0 {
		return peer
	}
	pip, err := netip.ParseAddr(peer)
	if err != nil || !c.trusts(pip) {
		return peer
	}
	var hops []string
	for _, line := range r.Header.Values(c.header) {
		hops = append(hops, strings.Split(line, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, ok := parseHop(hops[i])
		if !ok {
			return peer
		}
		if !c.trusts(ip) {
			return ip.String()
		}
	}
	// Every hop was a trusted proxy: the request comes from the proxy tier
	// itself, and its first hop is the closest thing to a client.
	if len(hops) > 0 {
		if ip, ok := parseHop(hops[0]); ok {
			return ip.String()
		}
	}
	return peer
}

// viaTrustedProxy reports whether the socket peer is a trusted proxy.
func (c *clientIPConfig) viaTrustedProxy(r *http.Request) bool {
	if c == nil || len(c.nets) == 0 {
		return false
	}
	pip, err := netip.ParseAddr(socketIP(r.RemoteAddr))
	return err == nil && c.trusts(pip)
}

// clientIP is the client address of a request, trusted-proxy aware.
func (s *Server) clientIP(r *http.Request) string {
	return s.clientIPCfg.Load().clientIP(r)
}

// requestScheme is the scheme the client used to reach this listener, for
// URLs quicgate builds about itself (the derived OIDC redirect URL). It
// believes X-Forwarded-Proto only from a trusted proxy.
func (s *Server) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if s.clientIPCfg.Load().viaTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

// socketIP is the address part of a host:port, or the whole string when it
// has no port.
func socketIP(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
