// Package wg embeds a userspace WireGuard endpoint: wireguard-go on a gVisor
// network stack, so quicgate needs no TUN device, no privileges and no change
// to the host's routing. This file is Part 1 of SPEC-wireguard.md: sites.
// A site is a plain WireGuard peer that fronts remote networks; an upstream
// that names a site is dialled through the tunnel (Manager.DialContext).
//
// Two rules from the spec shape the code. No implicit routing (S6): the tunnel
// is only ever entered through DialContext with a site, never by address. And
// no address changes owner inside a running stack instance (S40): a change of
// ownership rebuilds the device and the stack (S52), because a packet still
// queued for the old owner must not open a flow under the new one.
package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	mtu = 1420
	// siteUpWithin is how recent a handshake must be for a site to show as up.
	// Status only (S9): a dial is never refused because a handshake is old,
	// since in WireGuard it is the traffic that causes the handshake.
	siteUpWithin = 180 * time.Second
)

// Site is one WireGuard peer that fronts remote networks.
type Site struct {
	ID           int64
	Name         string
	PublicKey    string         // base64, 32 bytes
	PresharedKey string         // base64, 32 bytes; every peer has one (S37)
	Address      netip.Addr     // the site's /32 inside the tunnel network
	Networks     []netip.Prefix // remote prefixes reachable through the site
	Endpoint     string         // "host:port" when quicgate dials the site; "" when the site dials in
	Keepalive    int            // seconds; 0 = off
	Enabled      bool
}

// Config is the complete intended state of the endpoint.
type Config struct {
	PrivateKey string     // base64, 32 bytes
	ListenPort int        // UDP
	Address    netip.Addr // quicgate's own address in the tunnel network
	Sites      []Site
}

// SiteStatus is what the UI shows about a site.
type SiteStatus struct {
	ID            int64     `json:"id"`
	Up            bool      `json:"up"` // a handshake within the last three minutes
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"` // where the peer was last seen
	RxBytes       uint64    `json:"rxBytes"`
	TxBytes       uint64    `json:"txBytes"`
	Connections   int       `json:"connections"` // open connections through the site
	// Warning is a problem of this site alone, such as an endpoint name that
	// does not resolve. The site is configured without what failed.
	Warning string `json:"warning,omitempty"`
}

// instance is one device with its stack. It is never reconfigured in a way
// that changes who owns an address: that takes a new instance.
type instance struct {
	id   uint64
	dev  *device.Device
	net  *netstack.Net
	port int
	addr netip.Addr
	key  string
	// owned remembers every prefix a site has owned in this instance, also
	// after the site lost it, so it is never handed to another site here.
	owned map[netip.Prefix]int64
}

// Manager owns the endpoint. Use New.
type Manager struct {
	mu     sync.Mutex
	inst   *instance
	nextID uint64
	sites  map[int64]Site
	conns  map[int64]map[*trackedConn]struct{}
	resets uint64 // controlled resets so far
	logf   func(string, ...any)
	// resolved is the address each site's endpoint name last resolved to, and
	// warnings what went wrong for a single site. lookup is replaced in tests.
	resolved map[int64]string
	warnings map[int64]string
	lookup   func(ctx context.Context, endpoint string) (string, error)
}

// New returns a Manager with nothing running. Apply starts it.
func New() *Manager {
	return &Manager{sites: map[int64]Site{}, conns: map[int64]map[*trackedConn]struct{}{}, logf: log.Printf,
		resolved: map[int64]string{}, warnings: map[int64]string{}, lookup: resolveEndpoint}
}

// ErrNoFallback marks every refusal to dial through a site. The caller must
// treat it as final and never try the address on the host network (S8).
var ErrNoFallback = errors.New("not reachable through the WireGuard site, and never dialled outside it")

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("a WireGuard key is 32 bytes in base64")
	}
	return hex.EncodeToString(raw), nil
}

// resolveTimeout bounds one endpoint lookup, so a slow resolver cannot hold
// up a reload of the whole proxy.
const resolveTimeout = 3 * time.Second

// resolveEndpoint turns "host:port" into an IP literal with a port, which is
// all wireguard-go accepts.
func resolveEndpoint(ctx context.Context, endpoint string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", fmt.Errorf("endpoint %q: %q is not a port", endpoint, port)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, lerr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if lerr != nil || len(ips) == 0 {
			return "", fmt.Errorf("endpoint %q does not resolve: %v", endpoint, lerr)
		}
		ip = ips[0]
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)).String(), nil
}

// peerIPC renders one site as wireguard-go configuration. AllowedIPs are
// always written whole (S41), never patched. endpoint is the resolved
// endpoint to write, or "" to leave the peer's endpoint as it is.
func peerIPC(s Site, endpoint string) (string, error) {
	pub, err := keyHex(s.PublicKey)
	if err != nil {
		return "", fmt.Errorf("site %q public key: %w", s.Name, err)
	}
	psk, err := keyHex(s.PresharedKey)
	if err != nil {
		return "", fmt.Errorf("site %q preshared key: %w", s.Name, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\npreshared_key=%s\n", pub, psk)
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", s.Keepalive)
	fmt.Fprintf(&b, "allowed_ip=%s\n", netip.PrefixFrom(s.Address, s.Address.BitLen()))
	for _, n := range s.Networks {
		fmt.Fprintf(&b, "allowed_ip=%s\n", n.Masked())
	}
	return b.String(), nil
}

func enabledSites(cfg Config) []Site {
	var out []Site
	for _, s := range cfg.Sites {
		if s.Enabled {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// prefixesOf lists everything a site owns: its /32 and its networks.
func prefixesOf(s Site) []netip.Prefix {
	out := []netip.Prefix{netip.PrefixFrom(s.Address, s.Address.BitLen())}
	for _, n := range s.Networks {
		out = append(out, n.Masked())
	}
	return out
}

// needsReset reports whether cfg changes who owns an address the instance has
// already seen, or something only a new device can take (S40).
func (in *instance) needsReset(cfg Config) (bool, string) {
	if in.key != cfg.PrivateKey {
		return true, "the server key changed"
	}
	if in.port != cfg.ListenPort {
		return true, "the listen port changed"
	}
	if in.addr != cfg.Address {
		return true, "the tunnel address changed"
	}
	for _, s := range enabledSites(cfg) {
		for _, p := range prefixesOf(s) {
			for owned, owner := range in.owned {
				if owner != s.ID && owned.Overlaps(p) {
					return true, fmt.Sprintf("%s was owned by another site in this stack instance", owned)
				}
			}
		}
	}
	return false, ""
}

// Apply makes the endpoint match cfg. It starts the device on first use,
// updates peers in place when nobody's addresses change hands, and rebuilds
// the device and the stack when they do. On failure nothing half-applied is
// left running: the device is down and every connection closed.
func (m *Manager) Apply(ctx context.Context, cfg Config) error {
	if _, err := keyHex(cfg.PrivateKey); err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	if !cfg.Address.Is4() || cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return errors.New("the endpoint needs an IPv4 tunnel address and a UDP port")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inst != nil {
		reset, why := m.inst.needsReset(cfg)
		for _, s := range enabledSites(cfg) {
			// A new key is a new peer (S39): what the old key holder still has
			// in flight must not meet the new one's configuration.
			if old, ok := m.sites[s.ID]; ok && old.PublicKey != s.PublicKey {
				reset, why = true, fmt.Sprintf("site %q has a new key", s.Name)
			}
		}
		if reset {
			m.logf("wireguard: controlled reset: %s", why)
			m.stopLocked()
			m.resets++
		}
	}
	if m.inst == nil {
		if err := m.startLocked(cfg); err != nil {
			return err
		}
	}
	if err := m.syncPeersLocked(ctx, cfg, false); err != nil {
		m.logf("wireguard: applying the peers failed (%v), writing the whole configuration", err)
		if err := m.syncPeersLocked(ctx, cfg, true); err != nil {
			m.stopLocked()
			return fmt.Errorf("wireguard: configuration could not be applied, the endpoint is down: %w", err)
		}
	}
	return nil
}

func (m *Manager) startLocked(cfg Config) error {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, nil, mtu)
	if err != nil {
		return fmt.Errorf("wireguard: network stack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	key, _ := keyHex(cfg.PrivateKey)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", key, cfg.ListenPort)); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: cannot listen on UDP %d: %w", cfg.ListenPort, err)
	}
	m.nextID++
	m.inst = &instance{id: m.nextID, dev: dev, net: tnet, port: cfg.ListenPort, addr: cfg.Address, key: cfg.PrivateKey, owned: map[netip.Prefix]int64{}}
	m.logf("wireguard: listening on UDP %d as %s (stack instance %d)", cfg.ListenPort, cfg.Address, m.inst.id)
	return nil
}

// syncPeersLocked removes peers that are gone, closing their connections
// first (S41 order), then writes every enabled site.
func (m *Manager) syncPeersLocked(ctx context.Context, cfg Config, replaceAll bool) error {
	want := map[int64]Site{}
	for _, s := range enabledSites(cfg) {
		want[s.ID] = s
	}
	var b strings.Builder
	if replaceAll {
		b.WriteString("replace_peers=true\n")
	}
	for id, old := range m.sites {
		now, keep := want[id]
		if keep && now.PublicKey == old.PublicKey {
			continue
		}
		// Gone, disabled or re-keyed: its connections end before the peer does.
		m.closeSiteLocked(id)
		if !replaceAll {
			pub, err := keyHex(old.PublicKey)
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", pub)
		}
		delete(m.sites, id)
	}
	for _, s := range enabledSites(cfg) {
		// An endpoint that does not resolve is this site's problem, not the
		// endpoint's: the site is configured without it, can still call in, and
		// is tried again by Reresolve. The endpoint is only written when it is
		// new or changed, so a peer that roamed is not pulled back on every
		// reload.
		endpoint := ""
		delete(m.warnings, s.ID)
		if s.Endpoint != "" {
			ep, err := m.lookup(ctx, s.Endpoint)
			switch {
			case err != nil:
				m.warnings[s.ID] = err.Error()
				m.logf("wireguard: site %q: %v (configured without an endpoint for now)", s.Name, err)
			case ep != m.resolved[s.ID] || replaceAll || m.sites[s.ID].PublicKey != s.PublicKey:
				endpoint = ep
				m.resolved[s.ID] = ep
			}
		} else {
			delete(m.resolved, s.ID)
		}
		ipc, err := peerIPC(s, endpoint)
		if err != nil {
			return err
		}
		b.WriteString(ipc)
	}
	if b.Len() > 0 {
		if err := m.inst.dev.IpcSet(b.String()); err != nil {
			return err
		}
	}
	for id, s := range want {
		m.sites[id] = s
		for _, p := range prefixesOf(s) {
			m.inst.owned[p] = id
		}
	}
	return nil
}

// stopLocked closes every connection, then the device and its stack.
func (m *Manager) stopLocked() {
	for id := range m.conns {
		m.closeSiteLocked(id)
	}
	if m.inst != nil {
		m.inst.dev.Close() // closes the TUN side, which tears the stack down
		m.inst = nil
	}
	m.sites = map[int64]Site{}
	m.resolved = map[int64]string{}
}

// Reresolve looks the endpoint names up again and moves a site whose name now
// points elsewhere, as a dynamic-DNS name does when the address behind it
// changes. WireGuard itself never resolves a name twice.
func (m *Manager) Reresolve(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inst == nil {
		return
	}
	for id, s := range m.sites {
		if s.Endpoint == "" {
			continue
		}
		ep, err := m.lookup(ctx, s.Endpoint)
		if err != nil {
			m.warnings[id] = err.Error()
			continue
		}
		delete(m.warnings, id)
		if ep == m.resolved[id] {
			continue
		}
		pub, err := keyHex(s.PublicKey)
		if err != nil {
			continue
		}
		if err := m.inst.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", pub, ep)); err != nil {
			m.logf("wireguard: site %q: moving the endpoint to %s: %v", s.Name, ep, err)
			continue
		}
		m.logf("wireguard: site %q now at %s", s.Name, ep)
		m.resolved[id] = ep
	}
}

// Close stops the endpoint. Dials through a site fail afterwards.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

// Resets reports how many controlled resets have happened.
func (m *Manager) Resets() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resets
}

// trackedConn is a connection through a site, registered so that removing the
// site closes it (S42).
type trackedConn struct {
	net.Conn
	closed     atomic.Bool
	unregister func()
}

// Close unregisters the connection unless the manager already dropped it. It
// never waits on the manager while the manager waits on it: the flag is
// atomic, and closeSiteLocked takes no lock of the connection's.
func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.unregister()
	}
	return c.Conn.Close()
}

func (m *Manager) closeSiteLocked(id int64) {
	set := m.conns[id]
	delete(m.conns, id)
	for c := range set {
		c.closed.Store(true) // already unregistered
		_ = c.Conn.Close()
	}
}

// pickAddress resolves a target once and returns the first address that lies
// inside the site's networks (S7). The caller dials that literal; the name is
// not looked up again.
func pickAddress(ctx context.Context, s Site, host string) (netip.Addr, error) {
	inside := func(a netip.Addr) bool {
		a = a.Unmap()
		for _, n := range s.Networks {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !inside(ip) {
			return netip.Addr{}, fmt.Errorf("%s is not in the networks of site %q", ip, s.Name)
		}
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s does not resolve: %v", host, err)
	}
	for _, ip := range ips {
		if inside(ip) {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s resolves to no address in the networks of site %q", host, s.Name)
}

// DialContext connects to address ("host:port") through the site. Every
// failure wraps ErrNoFallback. A site is dialled whenever it is configured
// and enabled, whatever the age of its last handshake: the dial is what makes
// WireGuard shake hands (S8, S9).
func (m *Manager) DialContext(ctx context.Context, siteID int64, network, address string) (net.Conn, error) {
	fail := func(format string, args ...any) (net.Conn, error) {
		return nil, fmt.Errorf("%w: %s", ErrNoFallback, fmt.Sprintf(format, args...))
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fail("%v", err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fail("%q is not a port", port)
	}
	m.mu.Lock()
	inst := m.inst
	site, ok := m.sites[siteID]
	m.mu.Unlock()
	if inst == nil {
		return fail("the WireGuard endpoint is not running")
	}
	if !ok {
		return fail("site %d is not configured or not enabled", siteID)
	}

	ip, err := pickAddress(ctx, site, host)
	if err != nil {
		return fail("%v", err)
	}
	target := netip.AddrPortFrom(ip, uint16(p))
	var c net.Conn
	switch network {
	case "tcp", "tcp4":
		c, err = inst.net.DialContextTCPAddrPort(ctx, target)
	case "udp", "udp4":
		c, err = inst.net.DialUDPAddrPort(netip.AddrPort{}, target)
	default:
		return fail("network %q is not supported through a site", network)
	}
	if err != nil {
		return fail("site %q, %s: %v", site.Name, target, err)
	}

	// Register, unless the site went away while the dial was in flight: then
	// the connection must not outlive it (S2).
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.sites[siteID]; !ok || m.inst != inst || cur.PublicKey != site.PublicKey {
		_ = c.Close()
		return fail("site %q was removed while connecting", site.Name)
	}
	tc := &trackedConn{Conn: c}
	tc.unregister = func() {
		m.mu.Lock()
		delete(m.conns[siteID], tc)
		m.mu.Unlock()
	}
	if m.conns[siteID] == nil {
		m.conns[siteID] = map[*trackedConn]struct{}{}
	}
	m.conns[siteID][tc] = struct{}{}
	return tc, nil
}

// Status reports every configured site.
func (m *Manager) Status() []SiteStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inst == nil {
		return nil
	}
	dump, err := m.inst.dev.IpcGet()
	if err != nil {
		return nil
	}
	byKey := map[string]*SiteStatus{}
	var cur *SiteStatus
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			cur = &SiteStatus{}
			byKey[v] = cur
		case "last_handshake_time_sec":
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 && cur != nil {
				cur.LastHandshake = time.Unix(sec, 0).UTC()
				cur.Up = time.Since(cur.LastHandshake) < siteUpWithin
			}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	out := make([]SiteStatus, 0, len(m.sites))
	for id, s := range m.sites {
		st := SiteStatus{ID: id}
		if pub, err := keyHex(s.PublicKey); err == nil && byKey[pub] != nil {
			st = *byKey[pub]
			st.ID = id
		}
		st.Connections = len(m.conns[id])
		st.Warning = m.warnings[id]
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
