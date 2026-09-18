package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// The private entrance (SPEC-wireguard.md part 2): quicgate listens on its
// own address inside the WireGuard tunnel and serves the same routing table
// there. A request that arrives this way carries its peer in the context, and
// only the tunnel's listeners put it there (S11): nothing ever concludes from
// an address that a request came through the VPN.
//
// On these listeners there is no trusted-proxy rewriting and no PROXY
// protocol (S12), no auto-ban (S18), and no HTTP/3 advertisement (S13).

type vpnPeerKey struct{}

// vpnPeerOf reports the WireGuard peer a request came from, if it came
// through the tunnel.
func vpnPeerOf(r *http.Request) (wg.Peer, bool) {
	p, ok := r.Context().Value(vpnPeerKey{}).(wg.Peer)
	return p, ok
}

func viaVPN(r *http.Request) bool {
	_, ok := vpnPeerOf(r)
	return ok
}

// vpnOwner is who an SSO-enrolled device belongs to, with the groups from the
// owner's last renewal.
type vpnOwner struct {
	provider int64
	sub      string
	groups   map[string]bool
}

// vpnSubjectMatches reports whether a VPN subject names the peer. Groups and
// users are only ever matched together with their identity provider (S53).
func (e *Engine) vpnSubjectMatches(s store.VPNSubject, p wg.Peer) bool {
	switch s.Kind {
	case "any":
		return true
	case "site":
		return p.Site
	case "device":
		return !p.Site
	case "peer":
		return s.Peer == p.Key
	}
	if p.Site {
		return false
	}
	owners := e.vpnOwners.Load()
	if owners == nil {
		return false
	}
	o, ok := (*owners)[p.ID]
	if !ok || o.provider != s.Provider {
		return false
	}
	switch s.Kind {
	case "any-user":
		return true
	case "user":
		return o.sub == s.Sub
	case "group":
		return o.groups[s.Group]
	}
	return false
}

// subjectMatchesOwner is vpnSubjectMatches for a person rather than a peer:
// policies and enrolment are decided before a device exists.
func subjectMatchesOwner(s store.VPNSubject, provider int64, sub string, groups []string) bool {
	if s.Provider != provider {
		return false
	}
	switch s.Kind {
	case "any-user":
		return true
	case "user":
		return s.Sub == sub
	case "group":
		for _, g := range groups {
			if g == s.Group {
				return true
			}
		}
	}
	return false
}

// serveTunnel runs quicgate's listeners for one instance of the tunnel's
// network stack. They end when the instance does.
func (e *Engine) serveTunnel(tcp map[uint16]net.Listener, udp map[uint16]net.PacketConn) {
	withPeer := func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			c = tc.NetConn()
		}
		if pc, ok := c.(wg.PeerConn); ok {
			return context.WithValue(ctx, vpnPeerKey{}, pc.Peer())
		}
		return ctx
	}
	// Only connections that carry a peer are served at all.
	guard := func(next http.HandlerFunc) http.Handler {
		return e.accessLog.wrap(func(w http.ResponseWriter, r *http.Request) {
			if !viaVPN(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
		})
	}
	if ln := tcp[80]; ln != nil {
		srv := &http.Server{Handler: guard(e.serveHTTP), ConnContext: withPeer, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: publicIdleTimeout}
		go func() { _ = srv.Serve(ln) }()
	}
	if ln := tcp[443]; ln != nil && !e.cfg.DisableTLS {
		srv := &http.Server{Handler: guard(e.serveHTTPS), ConnContext: withPeer, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: publicIdleTimeout}
		go func() { _ = srv.Serve(tls.NewListener(ln, e.tlsConfigFor(true))) }()
	}
	if pc := udp[53]; pc != nil {
		go e.serveTunnelDNSUDP(pc)
	}
	if ln := tcp[53]; ln != nil {
		go e.serveTunnelDNSTCP(ln)
	}
}

// ---- tunnel DNS (S20) ----

const (
	dnsMaxUDPQuery   = 512
	dnsMaxTCPMessage = 4096
	dnsUpstreamWait  = 2 * time.Second
	dnsInFlight      = 256
)

var dnsSlots = make(chan struct{}, dnsInFlight)

// hostResolvers lists the resolvers of the machine quicgate runs on.
func hostResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, netip.AddrPortFrom(ip, 53).String())
			}
		}
	}
	return out
}

// ownName reports whether a DNS name is one of quicgate's configured hosts.
func (e *Engine) ownName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name != "" && e.table.Load().lookup(name) != nil
}

// answerDNS builds the answer for one query, or returns nil when the query
// has to be relayed. Only the question is parsed.
func (e *Engine) answerDNS(query []byte) (answer []byte, relay bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	if !e.ownName(q.Name.String()) {
		return nil, true
	}
	st := e.wgState.Load()
	if st == nil || !st.network.IsValid() {
		return nil, false
	}
	// Our own names: A is quicgate's tunnel address, every other type is
	// NODATA. Authoritative, never "authenticated data": a synthesised answer
	// must not look like a validated one.
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: hdr.ID, Response: true, Authoritative: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q}}
	if q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET {
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: wg.TunnelAddress(st.network).As4()},
		}}
	}
	out, err := resp.Pack()
	if err != nil {
		return nil, false
	}
	return out, false
}

// clientUDPLimit reads the EDNS size a query announces, capped at 1232.
func clientUDPLimit(query []byte) int {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return dnsMaxUDPQuery
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return dnsMaxUDPQuery
		}
		if h.Type == dnsmessage.TypeOPT {
			size := int(h.Class)
			if size < dnsMaxUDPQuery {
				return dnsMaxUDPQuery
			}
			if size > 1232 {
				return 1232
			}
			return size
		}
		if p.SkipAdditional() != nil {
			return dnsMaxUDPQuery
		}
	}
}

// truncated answers with the question only and TC set, so the client retries
// over TCP. A reply that does not fit is never forwarded cut off.
func truncated(query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: hdr.ID, Response: true, Truncated: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q}}
	out, _ := m.Pack()
	return out
}

func servfail(query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: hdr.ID, Response: true, RCode: dnsmessage.RCodeServerFailure, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true}}
	if q, err := p.Question(); err == nil {
		m.Questions = []dnsmessage.Question{q}
	}
	out, _ := m.Pack()
	return out
}

// relayDNS sends the query, as it came, to the host's resolvers over its own
// socket, and returns the reply as it came. One socket per query: a reply is
// only ever accepted on the socket that asked, so two peers with the same id
// and question cannot get each other's answers.
func relayDNS(query []byte, network string) ([]byte, error) {
	select {
	case dnsSlots <- struct{}{}:
		defer func() { <-dnsSlots }()
	default:
		return nil, errors.New("too many DNS queries in flight")
	}
	var lastErr error = errors.New("no resolver configured on this machine")
	for _, resolver := range hostResolvers() {
		c, err := net.DialTimeout(network, resolver, dnsUpstreamWait)
		if err != nil {
			lastErr = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(dnsUpstreamWait))
		reply, err := exchangeDNS(c, query, network == "tcp")
		c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		// The reply must answer this query.
		if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
			lastErr = errors.New("the resolver's reply does not match the query")
			continue
		}
		return reply, nil
	}
	return nil, lastErr
}

func exchangeDNS(c net.Conn, query []byte, framed bool) ([]byte, error) {
	if !framed {
		if _, err := c.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535) // a whole datagram, so nothing is cut off unnoticed
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	msg := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := readFull(c, l[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := readFull(c, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// dnsRate allows each peer address a bounded number of queries per second.
type dnsRate struct {
	mu   sync.Mutex
	at   map[netip.Addr]time.Time
	used map[netip.Addr]int
}

const dnsPerSecond = 50

func (d *dnsRate) allow(a netip.Addr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if d.at == nil || len(d.at) > 4096 {
		d.at, d.used = map[netip.Addr]time.Time{}, map[netip.Addr]int{}
	}
	if now.Sub(d.at[a]) >= time.Second {
		d.at[a], d.used[a] = now, 0
	}
	d.used[a]++
	return d.used[a] <= dnsPerSecond
}

func (e *Engine) serveTunnelDNSUDP(pc net.PacketConn) {
	var rate dnsRate
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ap, err := netip.ParseAddrPort(from.String())
		if err != nil || n > dnsMaxUDPQuery {
			continue
		}
		if _, ok := e.wg.PeerOf(ap.Addr()); !ok || !rate.allow(ap.Addr()) {
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			answer, relay := e.answerDNS(query)
			if relay {
				reply, err := relayDNS(query, "udp")
				switch {
				case err != nil:
					answer = servfail(query)
				case len(reply) > clientUDPLimit(query):
					answer = truncated(query)
				default:
					answer = reply
				}
			}
			if answer != nil {
				_, _ = pc.WriteTo(answer, from)
			}
		}()
	}
}

func (e *Engine) serveTunnelDNSTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for i := 0; i < 32; i++ {
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var l [2]byte
				if _, err := readFull(c, l[:]); err != nil {
					return
				}
				size := int(l[0])<<8 | int(l[1])
				if size == 0 || size > dnsMaxTCPMessage {
					return
				}
				query := make([]byte, size)
				if _, err := readFull(c, query); err != nil {
					return
				}
				answer, relay := e.answerDNS(query)
				if relay {
					if reply, err := relayDNS(query, "tcp"); err == nil {
						answer = reply
					} else {
						answer = servfail(query)
					}
				}
				if answer == nil {
					return
				}
				if _, err := c.Write(append([]byte{byte(len(answer) >> 8), byte(len(answer))}, answer...)); err != nil {
					return
				}
			}
		}()
	}
}

// wgDevices builds the devices of the endpoint's configuration, and the table
// of who owns them. A device is in the configuration only while it may be
// used: enabled, not revoked, not expired, and for a person's device only
// while the owner's lease runs and only with the routes the owner's groups
// grant (S24, S26). now is passed in so that one reload sees one moment.
func (e *Engine) wgDevices(now time.Time, lanAccess bool) ([]wg.Device, map[int64]vpnOwner) {
	stored, err := e.store.ListWGDevices()
	if err != nil {
		log.Printf("wireguard: devices: %v", err)
		return nil, nil
	}
	sessions := map[string]store.VPNSession{}
	if all, err := e.store.ListVPNSessions(); err == nil {
		for _, s := range all {
			sessions[ownerKey(s.Provider, s.Sub)] = s
		}
	}
	policies, _ := e.store.ListVPNPolicies()
	enrol := e.portalEnrolment()
	owners := map[int64]vpnOwner{}
	var out []wg.Device
	for _, d := range stored {
		if !d.Enabled || d.RevokedAt != "" || d.PresharedKey == "" {
			continue
		}
		addr, err := netip.ParseAddr(d.Address)
		if err != nil {
			continue
		}
		dev := wg.Device{ID: d.ID, Name: d.Name, Owner: d.Email, PublicKey: d.PublicKey, PresharedKey: d.PresharedKey, Address: addr}
		switch d.Kind {
		case "admin":
			dev.Owner = "admin"
		case "breakglass":
			dev.Owner = "break-glass"
			if d.ExpiresAt != "" {
				until, err := time.Parse(time.RFC3339, d.ExpiresAt)
				if err != nil || !now.Before(until) {
					continue
				}
				dev.Until = until
			}
			if lanAccess {
				dev.Routes = wgRoutes(d.Routes)
			}
		case "sso":
			s, ok := sessions[ownerKey(d.Provider, d.Sub)]
			if !ok || !s.Live(now) || e.store.VPNOwnerBlocked(d.Provider, d.Sub) {
				continue
			}
			// Still one of the people who may have devices at all?
			allowed := false
			for _, subj := range enrol[d.Provider] {
				allowed = allowed || subjectMatchesOwner(subj, s.Provider, s.Sub, s.Groups)
			}
			if !allowed {
				continue
			}
			dev.Until = s.AccessUntil()
			groups := map[string]bool{}
			for _, g := range s.Groups {
				groups[g] = true
			}
			owners[d.ID] = vpnOwner{provider: s.Provider, sub: s.Sub, groups: groups}
			if lanAccess {
				for _, p := range policies {
					if subjectMatchesOwner(p.Subject, s.Provider, s.Sub, s.Groups) {
						dev.Routes = append(dev.Routes, wgRoutes(p.Routes)...)
					}
				}
			}
		default:
			continue
		}
		out = append(out, dev)
	}
	return out, owners
}

func ownerKey(provider int64, sub string) string {
	return strconv.FormatInt(provider, 10) + "/" + sub
}

func wgRoutes(in []store.VPNRoute) []wg.Route {
	var out []wg.Route
	for _, r := range in {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		route := wg.Route{Prefix: p.Masked(), Proto: r.Proto}
		if route.Proto == "" {
			route.Proto = "any"
		}
		ports, err := store.ParsePorts(r.Ports)
		if err != nil {
			continue
		}
		for _, pr := range ports {
			route.Ports = append(route.Ports, wg.PortRange{From: pr[0], To: pr[1]})
		}
		out = append(out, route)
	}
	return out
}

// portalEnrolment lists, per identity provider, who may have devices: the
// enrolment subjects of every enabled portal host.
func (e *Engine) portalEnrolment() map[int64][]store.VPNSubject {
	out := map[int64][]store.VPNSubject{}
	hosts, err := e.store.ListHosts()
	if err != nil {
		return out
	}
	for _, h := range hosts {
		if h.Enabled && h.Type == "vpn-portal" && h.Options.Portal != nil {
			out[h.Options.Portal.ProviderID] = append(out[h.Options.Portal.ProviderID], h.Options.Portal.Enrol...)
		}
	}
	return out
}

// ExplainRoute says whether routes would let a device reach dest
// ("address:port") from this machine, and why not. It applies the same checks
// the forwarder does, with the guard and the sites of the moment.
func (e *Engine) ExplainRoute(routes []store.VPNRoute, proto, dest string) (string, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(dest))
	if err != nil {
		return "", errors.New("the destination must look like 192.168.1.10:443")
	}
	if proto != "tcp" && proto != "udp" {
		return "", errors.New("the protocol must be tcp or udp")
	}
	_, network, _, err := WGSettings(e.store)
	if err != nil {
		return "", err
	}
	cfg := wg.Config{Tunnel: network, Guard: e.wgGuard()}
	if stored, err := e.store.ListWGSites(); err == nil {
		for _, s := range stored {
			if site, err := wgSite(s); err == nil {
				cfg.Sites = append(cfg.Sites, site)
			}
		}
	}
	return wg.Explain(cfg, wgRoutes(routes), proto, ap), nil
}
