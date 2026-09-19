package wg

// The LAN forwarder (SPEC-wireguard.md part 3, S26 to S31, S48, S49). With
// Config.Forward the stack's interface is promiscuous, and every TCP
// connection and UDP flow that is not for quicgate's own tunnel address ends
// up here. A flow is checked, recorded, registered under its device, and only
// then dialled, from the host network, by IP literal.
//
// The order of the checks is fixed (S28): who is asking; destinations nobody
// may reach; this machine's own addresses; policy. For TCP the decision falls
// before the handshake completes, so a refused connection is reset, never
// accepted and then closed.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Bounds (S49). They are counted limits; the measured thresholds belong to
// the release's load tests.
const (
	maxFlowsPerPeer = 512
	maxFlowsTotal   = 4096
	tcpInFlight     = 512 // half-open connections the forwarder holds
	forwardDialWait = 5 * time.Second
	udpIdle         = 60 * time.Second
	tcpIdle         = 2 * time.Hour
)

// PortRange is an inclusive range of ports.
type PortRange struct{ From, To uint16 }

// Route is one destination a device may reach: a prefix, a protocol and
// ports. No ports means every port.
type Route struct {
	Prefix netip.Prefix
	Proto  string // tcp | udp | any
	Ports  []PortRange
}

func (r Route) allows(proto string, dst netip.AddrPort) bool {
	if r.Proto != "any" && r.Proto != proto {
		return false
	}
	if !r.Prefix.Contains(dst.Addr()) {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if dst.Port() >= p.From && dst.Port() <= p.To {
			return true
		}
	}
	return false
}

// Guard is what the forwarder must know about the machine it runs on. The
// engine fills it in; every function may be nil.
type Guard struct {
	// OwnAddrs are this machine's addresses, and OwnNets the subnets on its
	// interfaces. A destination that is an own address is refused unless a
	// route names exactly that host and explicit ports (S48): a flow to
	// quicgate's own listeners would arrive there from a local address and
	// pass every access list that trusts the local network.
	OwnAddrs func() []netip.Addr
	OwnNets  func() []netip.Prefix
	// ListenerPorts are the ports quicgate itself listens on. On an own
	// address they are never reachable, whatever a route says.
	ListenerPorts func() []uint16
	// ProtectedAddrs are addresses to treat as this machine's own although
	// quicgate cannot see that they are: the Docker host in bridge networking,
	// a NAT alias. ProtectedEndpoints are refused outright.
	ProtectedAddrs     []netip.Addr
	ProtectedEndpoints []netip.AddrPort
}

// FlowRecord is one line of the flow log.
type FlowRecord struct {
	Time     time.Time `json:"ts"`
	Peer     string    `json:"peer"`
	Device   string    `json:"device"`
	Owner    string    `json:"owner,omitempty"`
	Source   string    `json:"src"`
	Dest     string    `json:"dst"`
	Proto    string    `json:"proto"`
	Verdict  string    `json:"verdict"` // allow | deny | end
	Reason   string    `json:"reason,omitempty"`
	BytesUp  int64     `json:"bytesUp,omitempty"`   // device to LAN
	BytesDn  int64     `json:"bytesDown,omitempty"` // LAN to device
	Duration float64   `json:"seconds,omitempty"`
}

// flowID is what re-evaluation needs to know about an open flow.
type flowID struct {
	proto string
	dst   netip.AddrPort
}

var (
	v4Loopback  = netip.MustParsePrefix("127.0.0.0/8")
	v4LinkLocal = netip.MustParsePrefix("169.254.0.0/16")
	v4Multicast = netip.MustParsePrefix("224.0.0.0/4")
	v4Reserved  = netip.MustParsePrefix("240.0.0.0/4")
	v4This      = netip.MustParsePrefix("0.0.0.0/8")
)

// neverRoutable names why nobody may reach dst, or "" (S28 step 2).
func neverRoutable(cfg Config, dst netip.AddrPort) string {
	a := dst.Addr()
	switch {
	case !a.Is4():
		return "only IPv4 is forwarded"
	case dst.Port() == 0:
		return "port 0"
	case v4Loopback.Contains(a):
		return "loopback"
	case v4LinkLocal.Contains(a):
		return "link-local (this includes cloud metadata addresses)"
	case v4Multicast.Contains(a):
		return "multicast"
	case v4Reserved.Contains(a), v4This.Contains(a):
		return "reserved address (this includes the limited broadcast)"
	case cfg.Tunnel.IsValid() && cfg.Tunnel.Contains(a):
		return "the tunnel network: peers never reach each other"
	}
	for _, s := range cfg.Sites {
		for _, n := range s.Networks {
			if n.Contains(a) {
				return "a site's network"
			}
		}
	}
	for _, e := range cfg.Guard.ProtectedEndpoints {
		if e == dst {
			return "a protected endpoint"
		}
	}
	// Broadcast and network addresses of the subnets this machine is really
	// on. A route's prefix is an authorization, not a subnet, so it is never
	// used for this: a /32 grant stays a grant of exactly that host, and both
	// addresses of a /31 are ordinary hosts (RFC 3021).
	if cfg.Guard.OwnNets != nil {
		for _, n := range cfg.Guard.OwnNets() {
			n = n.Masked()
			if !n.Addr().Is4() || n.Bits() > 30 || !n.Contains(a) {
				continue
			}
			if a == n.Addr() || a == lastV4(n) {
				return "the network or broadcast address of " + n.String()
			}
		}
	}
	return ""
}

func lastV4(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(b)
}

func isOwn(g Guard, a netip.Addr) bool {
	for _, p := range g.ProtectedAddrs {
		if p == a {
			return true
		}
	}
	if g.OwnAddrs != nil {
		for _, o := range g.OwnAddrs() {
			if o.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// decide applies S28 steps 2 to 4 for one device. It returns whether the flow
// is allowed and, when it is not, why.
func decide(cfg Config, routes []Route, proto string, dst netip.AddrPort) (bool, string) {
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if why := neverRoutable(cfg, dst); why != "" {
		return false, why
	}
	if isOwn(cfg.Guard, dst.Addr()) {
		if cfg.Guard.ListenerPorts != nil {
			for _, p := range cfg.Guard.ListenerPorts() {
				if p == dst.Port() {
					return false, "one of quicgate's own listeners: reach its hosts through the tunnel address instead"
				}
			}
		}
		for _, r := range routes {
			if r.Prefix.Bits() == 32 && len(r.Ports) > 0 && r.allows(proto, dst) {
				return true, ""
			}
		}
		return false, "this machine's own address: it needs a route for exactly this host with explicit ports"
	}
	for _, r := range routes {
		if r.allows(proto, dst) {
			return true, ""
		}
	}
	return false, "no route in the device's policy"
}

// flowConns holds what a flow has open, so closing the flow from outside
// works whether or not the dial has finished.
type flowConns struct {
	mu     sync.Mutex
	closed bool
	conns  []io.Closer
	ctx    context.Context // cancelled when the flow is closed, also mid-dial
	cancel context.CancelFunc
}

func (f *flowConns) add(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = c.Close()
		return false
	}
	f.conns = append(f.conns, c)
	return true
}

func (f *flowConns) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.cancel()
	for _, c := range f.conns {
		_ = c.Close()
	}
}

// installForwarder makes the interface promiscuous and takes every TCP
// connection and UDP flow no listener of quicgate's claims.
func (m *Manager) installForwarder(in *instance) error {
	if err := in.stack.promiscuous(); err != nil {
		return err
	}
	tcpFwd := tcp.NewForwarder(in.stack.s, 0, tcpInFlight, func(r *tcp.ForwarderRequest) { m.forwardTCP(in, r) })
	in.stack.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(in.stack.s, func(r *udp.ForwarderRequest) { m.forwardUDP(in, r) })
	in.stack.s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return nil
}

// admitFlow is the admission of S2 for a forwarded flow: under the manager's
// lock it finds the device behind the source, decides, takes the log record
// and registers the flow, before anything is dialled. It returns nil when the
// flow is refused.
func (m *Manager) admitFlow(in *instance, proto string, src, dst netip.AddrPort) (*tracked, *flowConns, peer) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := FlowRecord{Time: now, Source: src.String(), Dest: dst.String(), Proto: proto}
	deny := func(p peer, why string) (*tracked, *flowConns, peer) {
		rec.Verdict, rec.Reason, rec.Peer, rec.Device, rec.Owner = "deny", why, p.key, p.name, p.owner
		if m.record != nil {
			m.record(rec) // best effort
		}
		return nil, nil, p
	}
	if m.inst != in {
		return deny(peer{}, "the endpoint was reset")
	}
	p, ok := m.peerByAddrLocked(src.Addr())
	if !ok {
		return deny(peer{}, "no active device has this address")
	}
	if p.site || len(p.routes) == 0 {
		return deny(p, "this peer has no LAN access")
	}
	if allowed, why := decide(m.cfg, p.routes, proto, dst); !allowed {
		return deny(p, why)
	}
	total := 0
	for _, set := range m.flows {
		total += len(set)
	}
	if len(m.flows[p.key]) >= maxFlowsPerPeer || total >= maxFlowsTotal {
		return deny(p, "too many open flows")
	}
	// No record, no flow (S31).
	rec.Verdict, rec.Peer, rec.Device, rec.Owner = "allow", p.key, p.name, p.owner
	if m.record != nil && !m.record(rec) {
		rec.Verdict, rec.Reason = "deny", "the flow log is full"
		return nil, nil, p
	}
	ctx, cancel := context.WithCancel(context.Background())
	fc := &flowConns{ctx: ctx, cancel: cancel}
	t := &tracked{close: fc.close, flow: &flowID{proto: proto, dst: dst}}
	m.admitLocked(p.key, t)
	return t, fc, p
}

// endFlow unregisters a flow and writes its closing record, best effort.
func (m *Manager) endFlow(p peer, t *tracked, fc *flowConns, proto string, src, dst netip.AddrPort, began time.Time, up, down int64) {
	fc.close()
	m.release(p.key, t)
	if m.record != nil {
		m.record(FlowRecord{Time: time.Now(), Peer: p.key, Device: p.name, Owner: p.owner, Source: src.String(), Dest: dst.String(),
			Proto: proto, Verdict: "end", BytesUp: up, BytesDn: down, Duration: time.Since(began).Seconds()})
	}
}

func addrPort(a []byte, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a)
	return netip.AddrPortFrom(ip.Unmap(), port)
}

func (m *Manager) forwardTCP(in *instance, r *tcp.ForwarderRequest) {
	id := r.ID()
	src := addrPort(id.RemoteAddress.AsSlice(), id.RemotePort)
	dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
	began := time.Now()
	t, fc, p := m.admitFlow(in, "tcp", src, dst)
	if t == nil {
		r.Complete(true) // reset: the handshake never completes
		return
	}
	var up, down int64
	defer func() { m.endFlow(p, t, fc, "tcp", src, dst, began, up, down) }()

	// Dial first: a destination that does not answer is a reset for the
	// device, not an accepted connection that goes nowhere.
	ctx, cancel := context.WithTimeout(fc.ctx, forwardDialWait)
	var d net.Dialer
	out, err := d.DialContext(ctx, "tcp4", dst.String())
	cancel()
	if err != nil || !fc.add(out) {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	if !fc.add(client) {
		return
	}
	up, down = relay(client, out, tcpIdle, false)
}

func (m *Manager) forwardUDP(in *instance, r *udp.ForwarderRequest) {
	id := r.ID()
	src := addrPort(id.RemoteAddress.AsSlice(), id.RemotePort)
	dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
	began := time.Now()
	t, fc, p := m.admitFlow(in, "udp", src, dst)
	if t == nil {
		return
	}
	// The endpoint is created here, in the handler, so that the next packet of
	// the same flow finds it instead of asking for another admission.
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		m.endFlow(p, t, fc, "udp", src, dst, began, 0, 0)
		return
	}
	client := gonet.NewUDPConn(&wq, ep)
	go func() {
		var up, down int64
		defer func() { m.endFlow(p, t, fc, "udp", src, dst, began, up, down) }()
		if !fc.add(client) {
			return
		}
		var d net.Dialer
		ctx, cancel := context.WithTimeout(fc.ctx, forwardDialWait)
		out, err := d.DialContext(ctx, "udp4", dst.String())
		cancel()
		if err != nil || !fc.add(out) {
			return
		}
		up, down = relay(client, out, udpIdle, true)
	}()
}

// maxDatagram is the largest UDP payload there is: a read into a buffer of
// this size never cuts a datagram short.
const maxDatagram = 65535

// relay copies both ways until either side ends or nothing moved for idle.
// For datagrams every read is one message and is written as one: the buffer
// holds the largest datagram there is, so none is cut short (a 32 KiB buffer
// silently delivered the first 32 KiB of a larger one, QG-11), and an empty
// datagram is a message too.
func relay(a, b net.Conn, idle time.Duration, datagrams bool) (aToB, bToA int64) {
	var wg sync.WaitGroup
	size := 32 << 10
	if datagrams {
		size = maxDatagram
	}
	pipe := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		buf := make([]byte, size)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			c, err := src.Read(buf)
			if c > 0 || (datagrams && err == nil) {
				_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, werr := dst.Write(buf[:c]); werr != nil {
					break
				}
				*n += int64(c)
			}
			if err != nil {
				break
			}
		}
		// One direction ended: end the other too, so the flow does not linger
		// half open until its idle limit.
		_ = a.Close()
		_ = b.Close()
	}
	wg.Add(2)
	go pipe(b, a, &aToB)
	go pipe(a, b, &bToA)
	wg.Wait()
	return aToB, bToA
}

// reviewFlowsLocked closes the forwarded flows that the configuration just
// applied no longer allows: a route was removed, a guard changed (S30).
func (m *Manager) reviewFlowsLocked() {
	for key, set := range m.flows {
		p, ok := m.peers[key]
		for t := range set {
			if t.flow == nil {
				continue
			}
			allowed := ok && p.active(time.Now())
			if allowed {
				allowed, _ = decide(m.cfg, p.routes, t.flow.proto, t.flow.dst)
			}
			if !allowed {
				delete(set, t)
				t.closed.Store(true)
				t.close()
			}
		}
	}
}

// Explain says whether a device with these routes could reach dst, and why
// not. The admin UI uses it to test a policy without a device.
func Explain(cfg Config, routes []Route, proto string, dst netip.AddrPort) string {
	if ok, why := decide(cfg, routes, proto, dst); !ok {
		return "refused: " + why
	}
	return fmt.Sprintf("allowed: %s %s", proto, dst)
}
