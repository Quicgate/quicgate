// Package wg embeds a userspace WireGuard endpoint: wireguard-go on a gVisor
// network stack, so quicgate needs no TUN device, no privileges and no change
// to the host's routing. SPEC-wireguard.md is the design.
//
// Peers are sites (a WireGuard peer that fronts remote networks, reached with
// DialContext) and devices (a phone or a laptop that reaches quicgate's own
// listeners inside the tunnel, and, when it may, addresses on the LAN through
// the forwarder in forward.go).
//
// Rules from the spec that shape the code:
//
//   - No implicit routing (S6): the tunnel is only entered through DialContext
//     with a site, never by address, and no refusal is ever retried on the
//     host network (S8).
//   - The source address of a packet inside the stack identifies its peer
//     (S1): wireguard-go drops what a peer sends from outside its allowed
//     addresses. Every admission looks the peer up by that address and
//     registers what it admits under the peer, under one lock, so revoking a
//     peer closes everything it has and nothing slips in between (S2, S42).
//   - No address changes owner inside a running stack instance (S40): a
//     change of ownership rebuilds the device and the stack (S52).
package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	mtu = 1420
	// siteUpWithin is how recent a handshake must be for a peer to show as up.
	// Status only (S9): a dial is never refused because a handshake is old,
	// since in WireGuard it is the traffic that causes the handshake.
	siteUpWithin = 180 * time.Second
)

// Site is a WireGuard peer that fronts remote networks.
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

// Device is a WireGuard peer that belongs to a person or to the admin: a
// phone, a laptop. It reaches quicgate's listeners in the tunnel. Only the
// caller decides which devices are in a Config at all: a revoked device, or
// one whose owner's lease ran out, is simply not there.
type Device struct {
	ID           int64
	Name         string
	Owner        string // who it belongs to, for logs and the flow log
	PublicKey    string
	PresharedKey string
	Address      netip.Addr
	// Until, when set, is the moment the device's authorization ends. It is
	// checked at every admission, so a late reload cannot extend access (S2).
	Until time.Time
	// Routes are the LAN destinations the device may reach through the
	// forwarder. Empty means none: the device reaches quicgate's own
	// listeners in the tunnel and nothing else.
	Routes []Route
}

// Config is the complete intended state of the endpoint.
type Config struct {
	PrivateKey string     // base64, 32 bytes
	ListenPort int        // UDP
	Address    netip.Addr // quicgate's own address in the tunnel network
	Tunnel     netip.Prefix
	Sites      []Site
	Devices    []Device
	// Forward switches the LAN forwarder on. Without it the stack only takes
	// packets for its own address.
	Forward bool
	Guard   Guard
}

// PeerStatus is what the UI shows about a peer.
type PeerStatus struct {
	ID            int64     `json:"id"`
	Up            bool      `json:"up"` // a handshake within the last three minutes
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"` // where the peer was last seen
	RxBytes       uint64    `json:"rxBytes"`
	TxBytes       uint64    `json:"txBytes"`
	Connections   int       `json:"connections"` // open connections and flows of the peer
	// Warning is a problem of this peer alone, such as an endpoint name that
	// does not resolve. The peer is configured without what failed.
	Warning string `json:"warning,omitempty"`
}

// SiteStatus is the old name of PeerStatus.
type SiteStatus = PeerStatus

// peer is a site or a device as the manager sees it.
type peer struct {
	key       string // "site:1", "device:7"
	site      bool
	id        int64
	name      string
	owner     string
	publicKey string
	psk       string
	address   netip.Addr
	networks  []netip.Prefix
	endpoint  string
	keepalive int
	until     time.Time
	routes    []Route
}

func sitePeer(s Site) peer {
	return peer{key: "site:" + strconv.FormatInt(s.ID, 10), site: true, id: s.ID, name: s.Name, publicKey: s.PublicKey,
		psk: s.PresharedKey, address: s.Address, networks: s.Networks, endpoint: s.Endpoint, keepalive: s.Keepalive}
}

func devicePeer(d Device) peer {
	return peer{key: "device:" + strconv.FormatInt(d.ID, 10), id: d.ID, name: d.Name, owner: d.Owner, publicKey: d.PublicKey,
		psk: d.PresharedKey, address: d.Address, until: d.Until, routes: d.Routes}
}

// Peer is what an admission learns about who is at the other end.
type Peer struct {
	Key    string // "site:1", "device:7"
	Site   bool
	ID     int64
	Name   string
	Owner  string
	Routes []Route
}

func (p peer) public() Peer {
	return Peer{Key: p.key, Site: p.site, ID: p.id, Name: p.name, Owner: p.owner, Routes: p.routes}
}

// active reports whether the peer's authorization still runs.
func (p peer) active(now time.Time) bool { return p.until.IsZero() || now.Before(p.until) }

// prefixes lists everything a peer owns: its /32 and, for a site, its networks.
func (p peer) prefixes() []netip.Prefix {
	out := []netip.Prefix{netip.PrefixFrom(p.address, p.address.BitLen())}
	for _, n := range p.networks {
		out = append(out, n.Masked())
	}
	return out
}

// instance is one device with its stack. It is never reconfigured in a way
// that changes who owns an address: that takes a new instance.
type instance struct {
	id    uint64
	dev   *device.Device
	stack *netStack
	port  int
	addr  netip.Addr
	key   string
	fwd   bool
	// owned remembers every prefix a peer has owned in this instance, also
	// after the peer lost it, so it is never handed to another peer here.
	owned map[netip.Prefix]string
}

// Listeners is what quicgate serves inside the tunnel, on its own address.
// OnStart is called for every new stack instance, because its listeners die
// with it. The listeners close when the instance stops.
type Listeners struct {
	TCP     []uint16
	UDP     []uint16
	OnStart func(tcp map[uint16]net.Listener, udp map[uint16]net.PacketConn)
}

// Manager owns the endpoint. Use New.
type Manager struct {
	mu     sync.Mutex
	inst   *instance
	nextID uint64
	cfg    Config
	peers  map[string]peer
	flows  map[string]map[*tracked]struct{}
	resets uint64 // controlled resets so far
	logf   func(string, ...any)
	listen Listeners
	// resolved is the address each peer's endpoint name last resolved to, and
	// warnings what went wrong for a single peer. lookup is replaced in tests.
	resolved map[string]string
	warnings map[string]string
	lookup   func(ctx context.Context, endpoint string) (string, error)
	// lastSeen remembers, by public key, where each peer was last heard from.
	// A peer that only calls in cannot be called back after a restart unless
	// quicgate remembers where it was; with it, the peer is back in a second
	// instead of after its own no-reply timer, some 40 s later.
	lastSeen  map[string]string
	stateFile string
	// record is the flow log. An allowed flow whose record cannot be taken is
	// refused (S31).
	record func(FlowRecord) bool
}

// New returns a Manager with nothing running. Apply starts it.
func New() *Manager {
	return &Manager{peers: map[string]peer{}, flows: map[string]map[*tracked]struct{}{}, logf: log.Printf,
		resolved: map[string]string{}, warnings: map[string]string{}, lookup: resolveEndpoint, lastSeen: map[string]string{}}
}

// SetListeners says what to serve inside the tunnel. Call it before Apply.
func (m *Manager) SetListeners(l Listeners) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listen = l
}

// SetFlowLog sets where the forwarder records flows. Call it before Apply.
func (m *Manager) SetFlowLog(record func(FlowRecord) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record = record
}

// SetStateFile makes the manager remember across restarts where peers were
// last seen. Call it before Apply.
func (m *Manager) SetStateFile(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateFile = path
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	seen := map[string]string{}
	if json.Unmarshal(data, &seen) != nil {
		return
	}
	for k, v := range seen {
		if _, err := netip.ParseAddrPort(v); err == nil && len(k) < 64 {
			m.lastSeen[k] = v
		}
	}
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

// peerIPC renders one peer as wireguard-go configuration. AllowedIPs are
// always written whole (S41), never patched. endpoint is the endpoint to
// write, or "" to leave the peer's endpoint as it is.
func peerIPC(p peer, endpoint string, located bool) (string, error) {
	pub, err := keyHex(p.publicKey)
	if err != nil {
		return "", fmt.Errorf("%s %q public key: %w", kindOf(p), p.name, err)
	}
	psk, err := keyHex(p.psk)
	if err != nil {
		return "", fmt.Errorf("%s %q preshared key: %w", kindOf(p), p.name, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\npreshared_key=%s\n", pub, psk)
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	// Keepalives go to a peer quicgate can find. For one it has never heard
	// from they would only fail, every few seconds, for as long as it is away.
	keepalive := p.keepalive
	if !located {
		keepalive = 0
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	for _, n := range p.prefixes() {
		fmt.Fprintf(&b, "allowed_ip=%s\n", n)
	}
	return b.String(), nil
}

func kindOf(p peer) string {
	if p.site {
		return "site"
	}
	return "device"
}

// wanted lists the peers a Config asks for, in a stable order.
func wanted(cfg Config) []peer {
	var out []peer
	for _, s := range cfg.Sites {
		if s.Enabled {
			out = append(out, sitePeer(s))
		}
	}
	for _, d := range cfg.Devices {
		out = append(out, devicePeer(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// needsReset reports whether cfg changes who owns an address the instance has
// already seen, or something only a new device can take (S40).
func (in *instance) needsReset(cfg Config) (bool, string) {
	switch {
	case in.key != cfg.PrivateKey:
		return true, "the server key changed"
	case in.port != cfg.ListenPort:
		return true, "the listen port changed"
	case in.addr != cfg.Address:
		return true, "the tunnel address changed"
	case in.fwd != cfg.Forward:
		return true, "LAN access was switched"
	}
	for _, p := range wanted(cfg) {
		for _, pre := range p.prefixes() {
			for owned, owner := range in.owned {
				if owner != p.key && owned.Overlaps(pre) {
					return true, fmt.Sprintf("%s was owned by another peer in this stack instance", owned)
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
		for _, p := range wanted(cfg) {
			// A new key is a new peer (S39): what the old key holder still has
			// in flight must not meet the new one's configuration.
			if old, ok := m.peers[p.key]; ok && old.publicKey != p.publicKey {
				reset, why = true, fmt.Sprintf("%s %q has a new key", kindOf(p), p.name)
			}
		}
		if reset {
			m.logf("wireguard: controlled reset: %s", why)
			m.stopLocked()
			m.resets++
		}
	}
	m.cfg = cfg
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
	m.reviewFlowsLocked()
	return nil
}

func (m *Manager) startLocked(cfg Config) error {
	ns, err := newNetStack(cfg.Address, mtu)
	if err != nil {
		return fmt.Errorf("wireguard: network stack: %w", err)
	}
	in := &instance{stack: ns, port: cfg.ListenPort, addr: cfg.Address, key: cfg.PrivateKey, fwd: cfg.Forward, owned: map[netip.Prefix]string{}}
	if cfg.Forward {
		if err := m.installForwarder(in); err != nil {
			ns.Close()
			return fmt.Errorf("wireguard: forwarder: %w", err)
		}
	}
	dev := device.NewDevice(ns, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	key, _ := keyHex(cfg.PrivateKey)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", key, cfg.ListenPort)); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: cannot listen on UDP %d: %w", cfg.ListenPort, err)
	}
	in.dev = dev
	m.nextID++
	in.id = m.nextID
	m.inst = in
	lan := ""
	if cfg.Forward {
		lan = ", LAN access on"
	}
	m.logf("wireguard: listening on UDP %d as %s (stack instance %d%s)", cfg.ListenPort, cfg.Address, in.id, lan)
	m.startListenersLocked()
	return nil
}

// startListenersLocked opens quicgate's own listeners in the new instance and
// hands them to the engine.
func (m *Manager) startListenersLocked() {
	if m.listen.OnStart == nil {
		return
	}
	tcp, udp := map[uint16]net.Listener{}, map[uint16]net.PacketConn{}
	for _, port := range m.listen.TCP {
		ln, err := m.inst.stack.listenTCP(port)
		if err != nil {
			m.logf("wireguard: cannot listen on tcp %d in the tunnel: %v", port, err)
			continue
		}
		tcp[port] = &peerListener{Listener: ln, m: m}
	}
	for _, port := range m.listen.UDP {
		pc, err := m.inst.stack.listenUDP(port)
		if err != nil {
			m.logf("wireguard: cannot listen on udp %d in the tunnel: %v", port, err)
			continue
		}
		udp[port] = pc
	}
	go m.listen.OnStart(tcp, udp)
}

// syncPeersLocked removes peers that are gone, closing what they have first
// (S41 order), then writes every wanted peer.
func (m *Manager) syncPeersLocked(ctx context.Context, cfg Config, replaceAll bool) error {
	want := map[string]peer{}
	for _, p := range wanted(cfg) {
		want[p.key] = p
	}
	var b strings.Builder
	if replaceAll {
		b.WriteString("replace_peers=true\n")
	}
	for key, old := range m.peers {
		now, keep := want[key]
		if keep && now.publicKey == old.publicKey {
			continue
		}
		// Gone, disabled, expired or re-keyed: its connections end before the
		// peer does.
		m.closePeerLocked(key)
		if !replaceAll {
			pub, err := keyHex(old.publicKey)
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", pub)
		}
		delete(m.peers, key)
	}
	for _, p := range wanted(cfg) {
		// An endpoint that does not resolve is this peer's problem, not the
		// endpoint's: the peer is configured without it, can still call in, and
		// is tried again by Reresolve. The endpoint is only written when it is
		// new or changed, so a peer that roamed is not pulled back on every
		// reload.
		endpoint := ""
		delete(m.warnings, p.key)
		_, known := m.peers[p.key]
		switch {
		case p.endpoint != "":
			ep, err := m.lookup(ctx, p.endpoint)
			switch {
			case err != nil:
				m.warnings[p.key] = err.Error()
				m.logf("wireguard: %s %q: %v (configured without an endpoint for now)", kindOf(p), p.name, err)
			case ep != m.resolved[p.key] || replaceAll || !known:
				endpoint = ep
				m.resolved[p.key] = ep
			}
		case !known || replaceAll:
			// A peer that calls in: start from where it was last heard, so it
			// is called back at once after a restart or a reset. The address
			// was authenticated when it was learnt, and WireGuard replaces it
			// with the peer's real one at the first packet that checks out.
			endpoint = m.lastSeen[p.publicKey]
			delete(m.resolved, p.key)
		}
		located := endpoint != "" || m.resolved[p.key] != "" || m.lastSeen[p.publicKey] != ""
		ipc, err := peerIPC(p, endpoint, located)
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
	for key, p := range want {
		m.peers[key] = p
		for _, pre := range p.prefixes() {
			m.inst.owned[pre] = key
		}
	}
	return nil
}

// rememberLocked notes where every peer was last heard from.
func (m *Manager) rememberLocked() {
	if m.inst == nil {
		return
	}
	dump, err := m.inst.dev.IpcGet()
	if err != nil {
		return
	}
	changed := false
	var pub string
	var found []string // heard from for the first time
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			pub = ""
			if raw, err := hex.DecodeString(v); err == nil {
				pub = base64.StdEncoding.EncodeToString(raw)
			}
		case "endpoint":
			if pub != "" && m.lastSeen[pub] != v {
				if m.lastSeen[pub] == "" {
					found = append(found, pub)
				}
				m.lastSeen[pub], changed = v, true
			}
		}
	}
	// A site that called in for the first time can be found from now on: its
	// keepalives start here.
	for _, pub := range found {
		for _, p := range m.peers {
			if p.publicKey != pub || p.keepalive == 0 {
				continue
			}
			if key, err := keyHex(pub); err == nil {
				_ = m.inst.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", key, p.keepalive))
			}
		}
	}
	if changed && m.stateFile != "" {
		if data, err := json.Marshal(m.lastSeen); err == nil {
			tmp := m.stateFile + ".tmp"
			if os.WriteFile(tmp, data, 0o600) == nil {
				_ = os.Rename(tmp, m.stateFile)
			}
		}
	}
}

// Remember notes where the peers are now. The engine calls it now and then,
// and the manager itself before it stops.
func (m *Manager) Remember() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rememberLocked()
}

// stopLocked closes every connection, then the device and its stack.
func (m *Manager) stopLocked() {
	m.rememberLocked()
	for key := range m.flows {
		m.closePeerLocked(key)
	}
	if m.inst != nil {
		m.inst.dev.Close() // closes the stack too
		m.inst = nil
	}
	m.peers = map[string]peer{}
	m.resolved = map[string]string{}
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

// Reresolve looks the endpoint names up again and moves a peer whose name now
// points elsewhere, as a dynamic-DNS name does when the address behind it
// changes. WireGuard itself never resolves a name twice.
func (m *Manager) Reresolve(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inst == nil {
		return
	}
	for key, p := range m.peers {
		if p.endpoint == "" {
			continue
		}
		ep, err := m.lookup(ctx, p.endpoint)
		if err != nil {
			m.warnings[key] = err.Error()
			continue
		}
		delete(m.warnings, key)
		if ep == m.resolved[key] {
			continue
		}
		pub, err := keyHex(p.publicKey)
		if err != nil {
			continue
		}
		if err := m.inst.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", pub, ep)); err != nil {
			m.logf("wireguard: %s %q: moving the endpoint to %s: %v", kindOf(p), p.name, ep, err)
			continue
		}
		m.logf("wireguard: %s %q now at %s", kindOf(p), p.name, ep)
		m.resolved[key] = ep
	}
}

// tracked is something a peer has open: a connection through a site, a
// connection to one of quicgate's listeners, a forwarded flow. Removing the
// peer closes it (S42).
type tracked struct {
	closed atomic.Bool
	close  func()  // closes the thing itself
	flow   *flowID // set for forwarded flows, for re-evaluation after a policy change
}

// admitLocked registers t under the peer. The caller holds m.mu and has
// checked that the peer is active.
func (m *Manager) admitLocked(key string, t *tracked) {
	if m.flows[key] == nil {
		m.flows[key] = map[*tracked]struct{}{}
	}
	m.flows[key][t] = struct{}{}
}

// release forgets t when it ends by itself. It never waits on the manager
// while the manager waits on it: the flag is atomic, and closePeerLocked
// takes no lock of the connection's.
func (m *Manager) release(key string, t *tracked) {
	if t.closed.CompareAndSwap(false, true) {
		m.mu.Lock()
		delete(m.flows[key], t)
		m.mu.Unlock()
	}
}

func (m *Manager) closePeerLocked(key string) {
	set := m.flows[key]
	delete(m.flows, key)
	for t := range set {
		t.closed.Store(true) // already unregistered
		t.close()
	}
}

// trackedConn is a net.Conn registered under a peer.
type trackedConn struct {
	net.Conn
	m   *Manager
	key string
	t   *tracked
}

func (c *trackedConn) Close() error {
	c.m.release(c.key, c.t)
	return c.Conn.Close()
}

// peerByAddrLocked finds the active peer that owns a source address (S1).
func (m *Manager) peerByAddrLocked(a netip.Addr) (peer, bool) {
	a = a.Unmap()
	now := time.Now()
	for _, p := range m.peers {
		if !p.active(now) {
			continue
		}
		if p.address == a {
			return p, true
		}
		for _, n := range p.networks {
			if n.Contains(a) {
				return p, true
			}
		}
	}
	return peer{}, false
}

// PeerOf reports the active peer behind a source address inside the tunnel.
func (m *Manager) PeerOf(a netip.Addr) (Peer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peerByAddrLocked(a)
	return p.public(), ok
}

// peerListener attributes every accepted connection to its peer and registers
// it there. A connection from an address no active peer owns is dropped.
type peerListener struct {
	net.Listener
	m *Manager
}

// PeerConn is a connection to one of quicgate's listeners in the tunnel.
type PeerConn interface {
	net.Conn
	Peer() Peer
}

type peerConn struct {
	*trackedConn
	peer Peer
}

func (c *peerConn) Peer() Peer { return c.peer }

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			c.Close()
			continue
		}
		l.m.mu.Lock()
		p, ok := l.m.peerByAddrLocked(ap.Addr())
		if !ok {
			l.m.mu.Unlock()
			c.Close()
			continue
		}
		t := &tracked{close: func() { _ = c.Close() }}
		l.m.admitLocked(p.key, t)
		l.m.mu.Unlock()
		return &peerConn{trackedConn: &trackedConn{Conn: c, m: l.m, key: p.key, t: t}, peer: p.public()}, nil
	}
}

// pickAddress resolves a target once and returns the first address that lies
// inside the site's networks (S7). The caller dials that literal; the name is
// not looked up again.
func pickAddress(ctx context.Context, p peer, host string) (netip.Addr, error) {
	inside := func(a netip.Addr) bool {
		a = a.Unmap()
		for _, n := range p.networks {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !inside(ip) {
			return netip.Addr{}, fmt.Errorf("%s is not in the networks of site %q", ip, p.name)
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
	return netip.Addr{}, fmt.Errorf("%s resolves to no address in the networks of site %q", host, p.name)
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
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil || pn == 0 {
		return fail("%q is not a port", port)
	}
	key := "site:" + strconv.FormatInt(siteID, 10)
	m.mu.Lock()
	inst := m.inst
	site, ok := m.peers[key]
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
	target := netip.AddrPortFrom(ip, uint16(pn))
	var c net.Conn
	switch network {
	case "tcp", "tcp4":
		c, err = inst.stack.dialTCP(ctx, target)
	case "udp", "udp4":
		c, err = inst.stack.dialUDP(target)
	default:
		return fail("network %q is not supported through a site", network)
	}
	if err != nil {
		return fail("site %q, %s: %v", site.name, target, err)
	}

	// Register, unless the site went away while the dial was in flight: then
	// the connection must not outlive it (S2).
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.peers[key]; !ok || m.inst != inst || cur.publicKey != site.publicKey {
		_ = c.Close()
		return fail("site %q was removed while connecting", site.name)
	}
	t := &tracked{close: func() { _ = c.Close() }}
	m.admitLocked(key, t)
	return &trackedConn{Conn: c, m: m, key: key, t: t}, nil
}

// statusLocked reads the device's view of its peers, by public key in hex.
func (m *Manager) statusLocked() map[string]*PeerStatus {
	byKey := map[string]*PeerStatus{}
	dump, err := m.inst.dev.IpcGet()
	if err != nil {
		return byKey
	}
	var cur *PeerStatus
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			cur = &PeerStatus{}
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
	return byKey
}

func (m *Manager) peerStatuses(sites bool) []PeerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inst == nil {
		return nil
	}
	byKey := m.statusLocked()
	out := []PeerStatus{}
	for key, p := range m.peers {
		if p.site != sites {
			continue
		}
		st := PeerStatus{ID: p.id}
		if pub, err := keyHex(p.publicKey); err == nil && byKey[pub] != nil {
			st = *byKey[pub]
			st.ID = p.id
		}
		st.Connections = len(m.flows[key])
		st.Warning = m.warnings[key]
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Status reports every configured site; nil while the endpoint is down.
func (m *Manager) Status() []PeerStatus { return m.peerStatuses(true) }

// DeviceStatus reports every configured device; nil while the endpoint is down.
func (m *Manager) DeviceStatus() []PeerStatus { return m.peerStatuses(false) }
