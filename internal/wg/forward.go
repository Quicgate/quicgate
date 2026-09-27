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
//
// Nothing on the packet path waits for the flow log (S31). An admission
// decides and reserves its place under the manager's lock, then waits for
// the record of the allowed flow to be written with the lock released, so a
// slow disk delays that one flow and not the tunnel's other traffic, its DNS,
// a reload or the public proxy's dials through sites. gVisor calls the UDP
// forwarder on the goroutine that decrypts the tunnel, so UDP admissions are
// handed to workers and the handler itself never blocks.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Bounds (S49). They are counted limits; the measured thresholds belong to
// the release's load tests. With the relay buffers below, an open UDP flow
// holds about 66 KiB of relay buffers and a TCP flow 64 KiB, before the
// stack's own per-endpoint buffers (stack.go).
const (
	maxFlowsPerPeer = 512
	maxFlowsTotal   = 4096
	// maxPendingPerPeer bounds the flows of one peer that are between
	// admission and relay: waiting for their record, or dialling. The TCP
	// forwarder holds tcpInFlight half-open connections in all, and without
	// this one device could take every one of them.
	maxPendingPerPeer = 64
	tcpInFlight       = 512 // half-open connections the forwarder holds
	forwardDialWait   = 5 * time.Second
	udpIdle           = 60 * time.Second
	tcpIdle           = 2 * time.Hour
	// UDP admissions wait for a worker in a bounded queue, with a share per
	// source address so one device cannot fill it for the others.
	udpAdmitWorkers   = 8
	udpAdmitQueue     = 256
	udpAdmitPerSource = 32
	// A refused UDP flow is remembered by its 4-tuple: its next datagrams are
	// dropped without a decision or a record. A reload forgets the refusals,
	// because it may have changed what is allowed.
	denyCacheFor = 30 * time.Second
	denyCacheMax = 8192
	// denyRecordsPerSecond caps the deny records written per peer. What is
	// suppressed is counted (FlowRecordsSuppressed).
	denyRecordsPerSecond = 10
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
// engine fills it in; every function may be nil. The functions are asked on
// every admission, so they should answer from a cache (the engine's do), and
// the forwarder never modifies what they return.
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

// flowKey is the 4-tuple of a flow with its protocol.
type flowKey struct {
	proto    string
	src, dst netip.AddrPort
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
	// settled is set once the flow is past its opening phase (dialled, or
	// gone), when it stops counting against its peer's pending flows.
	settled atomic.Bool
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

// udpAdmitter hands UDP admissions from the receive path to workers. The
// handler only checks the deny cache and queues the request; the first
// datagram travels with the request and reaches the endpoint once it exists.
// Datagrams of the same flow that arrive while its admission is pending are
// dropped, as are requests beyond the queue's size or a source's share of it.
type udpAdmitter struct {
	mu      sync.Mutex
	pending map[flowKey]struct{}
	bySrc   map[netip.Addr]int
	queue   chan udpRequest
}

type udpRequest struct {
	key flowKey
	r   *udp.ForwarderRequest
}

func newUDPAdmitter() *udpAdmitter {
	return &udpAdmitter{pending: map[flowKey]struct{}{}, bySrc: map[netip.Addr]int{}, queue: make(chan udpRequest, udpAdmitQueue)}
}

// enqueue takes the request unless the flow's admission is already pending,
// the source has its share of the queue, or the queue is full.
func (u *udpAdmitter) enqueue(k flowKey, r *udp.ForwarderRequest) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, dup := u.pending[k]; dup || u.bySrc[k.src.Addr()] >= udpAdmitPerSource {
		return false
	}
	select {
	case u.queue <- udpRequest{key: k, r: r}:
	default:
		return false
	}
	u.pending[k] = struct{}{}
	u.bySrc[k.src.Addr()]++
	return true
}

// settle forgets a pending admission once a worker is through with it.
func (u *udpAdmitter) settle(k flowKey) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.pending, k)
	if u.bySrc[k.src.Addr()] <= 1 {
		delete(u.bySrc, k.src.Addr())
	} else {
		u.bySrc[k.src.Addr()]--
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
	in.udp = newUDPAdmitter()
	// The handler reports whether it took the request: it always does, either
	// by creating an endpoint, by handing the request to an admission worker,
	// or by deciding to drop the packet itself, so the stack never answers a
	// tunnel packet with an ICMP error on our behalf.
	udpFwd := udp.NewForwarder(in.stack.s, func(r *udp.ForwarderRequest) bool { m.forwardUDP(in, r); return true })
	in.stack.s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	for i := 0; i < udpAdmitWorkers; i++ {
		go m.udpWorker(in)
	}
	return nil
}

// admission is the outcome of admitFlow: a registered flow, or the reason it
// was refused.
type admission struct {
	t      *tracked
	fc     *flowConns
	p      peer
	why    string
	record func(FlowRecord) bool
}

// admitFlow is the admission of S2 for a forwarded flow, in three steps.
// Under the manager's lock it finds the device behind the source, decides,
// and registers the flow as a reservation that counts against the budgets
// and that a revocation closes. With the lock released it waits for the
// record of the allowed flow to be written: no record, no flow (S31). Under
// the lock again it checks that the reservation survived, and only then does
// the flow exist. It returns no tracked flow when the flow is refused.
func (m *Manager) admitFlow(in *instance, proto string, src, dst netip.AddrPort) admission {
	rec := FlowRecord{Time: time.Now(), Source: src.String(), Dest: dst.String(), Proto: proto}

	m.mu.Lock()
	record := m.record
	p, why := m.decideLocked(in, proto, src, dst)
	if why != "" {
		m.mu.Unlock()
		return m.refuse(record, rec, p, why)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fc := &flowConns{ctx: ctx, cancel: cancel}
	t := &tracked{close: fc.close, flow: &flowID{proto: proto, dst: dst}}
	m.admitLocked(p.key, t)
	m.pending[p.key]++
	m.mu.Unlock()

	rec.Verdict, rec.Peer, rec.Device, rec.Owner = "allow", p.key, p.name, p.owner
	if record != nil && !record(rec) {
		m.dropReservation(p.key, t, fc)
		return m.refuse(record, rec, p, "the flow log is full")
	}

	m.mu.Lock()
	if t.closed.Load() || m.inst != in {
		// Revoked, or no longer allowed by a policy applied meanwhile, or the
		// stack was reset while the record was written. The record says
		// allow; the refusal that follows says what became of the flow.
		m.dropReservationLocked(p.key, t, fc)
		m.mu.Unlock()
		return m.refuse(record, rec, p, "the device or the endpoint went away while the flow was admitted")
	}
	m.mu.Unlock()
	return admission{t: t, fc: fc, p: p, record: record}
}

// decideLocked is the part of an admission that needs the manager's state:
// the peer behind the source, the policy, and the budgets. It returns the
// peer and, when the flow is refused, why. The caller holds m.mu.
func (m *Manager) decideLocked(in *instance, proto string, src, dst netip.AddrPort) (peer, string) {
	if m.inst != in {
		return peer{}, "the endpoint was reset"
	}
	p, ok := m.peerByAddrLocked(src.Addr())
	if !ok {
		return peer{}, "no active device has this address"
	}
	if p.site || len(p.routes) == 0 {
		return p, "this peer has no LAN access"
	}
	if allowed, why := decide(m.cfg, p.routes, proto, dst); !allowed {
		return p, why
	}
	if !m.roomLocked(p.key) {
		return p, "too many open flows"
	}
	if m.pending[p.key] >= maxPendingPerPeer {
		return p, "too many flows being opened at once"
	}
	return p, ""
}

// refuse writes the deny record, best effort and at most denyRecordsPerSecond
// per peer, and returns the refusal.
func (m *Manager) refuse(record func(FlowRecord) bool, rec FlowRecord, p peer, why string) admission {
	rec.Verdict, rec.Reason, rec.Peer, rec.Device, rec.Owner = "deny", why, p.key, p.name, p.owner
	if record != nil {
		if m.denyRecordAllowed(p.key, time.Now()) {
			record(rec)
		} else {
			m.suppressed.Add(1)
		}
	}
	return admission{p: p, why: why, record: record}
}

// dropReservation gives a reservation up before the flow exists.
func (m *Manager) dropReservation(key string, t *tracked, fc *flowConns) {
	m.mu.Lock()
	m.dropReservationLocked(key, t, fc)
	m.mu.Unlock()
}

func (m *Manager) dropReservationLocked(key string, t *tracked, fc *flowConns) {
	if !t.closed.Swap(true) {
		delete(m.flows[key], t)
	}
	m.settleLocked(key, fc)
	fc.close()
}

// settle ends the opening phase of a flow: it is relaying, or it is gone.
func (m *Manager) settle(key string, fc *flowConns) {
	if fc.settled.Load() {
		return
	}
	m.mu.Lock()
	m.settleLocked(key, fc)
	m.mu.Unlock()
}

func (m *Manager) settleLocked(key string, fc *flowConns) {
	if !fc.settled.CompareAndSwap(false, true) {
		return
	}
	if m.pending[key] <= 1 {
		delete(m.pending, key)
	} else {
		m.pending[key]--
	}
}

// denyRecordAllowed reports whether one more deny record of the peer may be
// written this second.
func (m *Manager) denyRecordAllowed(key string, now time.Time) bool {
	m.denyMu.Lock()
	defer m.denyMu.Unlock()
	if len(m.denyWin) > 4096 {
		m.denyWin = map[string]denyWindow{}
	}
	w := m.denyWin[key]
	if now.Sub(w.at) >= time.Second {
		w = denyWindow{at: now}
	}
	w.n++
	m.denyWin[key] = w
	return w.n <= denyRecordsPerSecond
}

// denyWindow counts one peer's deny records in the current second.
type denyWindow struct {
	at time.Time
	n  int
}

// recentlyDenied reports whether the flow was refused within denyCacheFor.
func (m *Manager) recentlyDenied(k flowKey, now time.Time) bool {
	m.denyMu.Lock()
	defer m.denyMu.Unlock()
	until, ok := m.denied[k]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(m.denied, k)
		return false
	}
	return true
}

// noteDenied remembers a refusal. When the cache is full, expired entries go
// first; when it is full of live ones, this refusal is not remembered.
func (m *Manager) noteDenied(k flowKey, now time.Time) {
	m.denyMu.Lock()
	defer m.denyMu.Unlock()
	if len(m.denied) >= denyCacheMax {
		for key, until := range m.denied {
			if now.After(until) {
				delete(m.denied, key)
			}
		}
		if len(m.denied) >= denyCacheMax {
			return
		}
	}
	m.denied[k] = now.Add(denyCacheFor)
}

// forgetDenials empties the deny cache: the configuration changed, and with
// it perhaps what is allowed.
func (m *Manager) forgetDenials() {
	m.denyMu.Lock()
	m.denied = map[flowKey]time.Time{}
	m.denyMu.Unlock()
}

// FlowRecordsSuppressed reports how many deny records were not written
// because a peer exceeded denyRecordsPerSecond. They count as lost
// best-effort records (S31).
func (m *Manager) FlowRecordsSuppressed() uint64 { return m.suppressed.Load() }

// endFlow unregisters a flow and writes its closing record, best effort.
func (m *Manager) endFlow(a admission, proto string, src, dst netip.AddrPort, began time.Time, up, down int64) {
	a.fc.close()
	m.mu.Lock()
	if a.t.closed.CompareAndSwap(false, true) {
		delete(m.flows[a.p.key], a.t)
	}
	m.settleLocked(a.p.key, a.fc)
	m.mu.Unlock()
	if a.record != nil {
		a.record(FlowRecord{Time: time.Now(), Peer: a.p.key, Device: a.p.name, Owner: a.p.owner, Source: src.String(), Dest: dst.String(),
			Proto: proto, Verdict: "end", BytesUp: up, BytesDn: down, Duration: time.Since(began).Seconds()})
	}
}

func addrPort(a []byte, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a)
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// forwardTCP runs on a goroutine of its own, one per half-open connection,
// so it may wait for the record and the dial.
func (m *Manager) forwardTCP(in *instance, r *tcp.ForwarderRequest) {
	id := r.ID()
	src := addrPort(id.RemoteAddress.AsSlice(), id.RemotePort)
	dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
	began := time.Now()
	a := m.admitFlow(in, "tcp", src, dst)
	if a.t == nil {
		r.Complete(true) // reset: the handshake never completes
		return
	}
	var up, down int64
	defer func() { m.endFlow(a, "tcp", src, dst, began, up, down) }()

	// Dial first: a destination that does not answer is a reset for the
	// device, not an accepted connection that goes nowhere.
	ctx, cancel := context.WithTimeout(a.fc.ctx, forwardDialWait)
	var d net.Dialer
	out, err := d.DialContext(ctx, "tcp4", dst.String())
	cancel()
	m.settle(a.p.key, a.fc)
	if err != nil || !a.fc.add(out) {
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
	if !a.fc.add(client) {
		return
	}
	up, down = relay(client, out, tcpIdle)
}

// forwardUDP runs on the tunnel's receive goroutine: it must not wait. A flow
// refused lately is dropped here; anything else is queued for a worker.
func (m *Manager) forwardUDP(in *instance, r *udp.ForwarderRequest) {
	id := r.ID()
	k := flowKey{proto: "udp", src: addrPort(id.RemoteAddress.AsSlice(), id.RemotePort), dst: addrPort(id.LocalAddress.AsSlice(), id.LocalPort)}
	if m.recentlyDenied(k, time.Now()) {
		return
	}
	in.udp.enqueue(k, r)
}

// udpWorker admits the queued UDP flows of one stack instance until it ends.
func (m *Manager) udpWorker(in *instance) {
	for {
		select {
		case req := <-in.udp.queue:
			m.admitUDP(in, req)
			in.udp.settle(req.key)
		case <-in.stack.done:
			return
		}
	}
}

func (m *Manager) admitUDP(in *instance, req udpRequest) {
	k := req.key
	began := time.Now()
	a := m.admitFlow(in, "udp", k.src, k.dst)
	if a.t == nil {
		m.noteDenied(k, time.Now())
		return
	}
	// The endpoint is created before the worker moves on, so the next
	// datagram of the flow finds it instead of asking for another admission.
	var wq waiter.Queue
	ep, terr := req.r.CreateEndpoint(&wq)
	if terr != nil {
		m.endFlow(a, "udp", k.src, k.dst, began, 0, 0)
		return
	}
	client := gonet.NewUDPConn(&wq, ep)
	go func() {
		var up, down int64
		defer func() { m.endFlow(a, "udp", k.src, k.dst, began, up, down) }()
		if !a.fc.add(client) {
			return
		}
		var d net.Dialer
		ctx, cancel := context.WithTimeout(a.fc.ctx, forwardDialWait)
		out, err := d.DialContext(ctx, "udp4", k.dst.String())
		cancel()
		m.settle(a.p.key, a.fc)
		if err != nil || !a.fc.add(out) {
			return
		}
		up, down = relayUDP(client, ep, &wq, out, udpIdle)
	}()
}

// Relay buffers (S49). A TCP flow reads each side into a stream buffer. A UDP
// flow needs a buffer that holds a whole datagram, because a datagram is
// delivered whole or not at all (QG-11): towards the tunnel that is the
// largest there is, since a LAN service may send one that large. From the
// tunnel a datagram arrives in one packet of the tunnel's MTU; only when the
// device sent it in IP fragments, which the stack reassembles, is it larger.
// So the tunnel side reads into a small buffer and borrows a large one for
// the rare reassembled datagram. Every buffer comes from a pool and goes back
// when the flow ends, so the relay's footprint is what the open flows hold.
const (
	streamBuf   = 32 << 10
	tunnelBuf   = 2048 // more than the MTU: one unfragmented datagram from the tunnel
	maxDatagram = 65535
)

var (
	streamBufs = &bufPool{size: streamBuf}
	tunnelBufs = &bufPool{size: tunnelBuf}
	largeBufs  = &bufPool{size: maxDatagram}
)

// bufPool hands out buffers of one size and takes them back.
type bufPool struct {
	size int
	pool sync.Pool
	// taken counts the buffers out at the moment, for the tests and the
	// measurement S49 asks for.
	taken atomic.Int64
}

func (p *bufPool) get() []byte {
	p.taken.Add(1)
	if b, ok := p.pool.Get().(*[]byte); ok {
		return (*b)[:p.size]
	}
	return make([]byte, p.size)
}

func (p *bufPool) put(b []byte) {
	if cap(b) < p.size {
		return
	}
	b = b[:p.size]
	p.pool.Put(&b)
	p.taken.Add(-1)
}

// source is one side of a flow as the relay reads it. next returns the next
// message, a whole datagram or what a stream had, valid until the next call;
// release returns the buffers to their pools.
type source interface {
	next(deadline time.Time) ([]byte, error)
	release()
}

// connSource reads a net.Conn into one pooled buffer.
type connSource struct {
	c    net.Conn
	pool *bufPool
	buf  []byte
}

func newConnSource(c net.Conn, pool *bufPool) *connSource {
	return &connSource{c: c, pool: pool, buf: pool.get()}
}

func (s *connSource) next(deadline time.Time) ([]byte, error) {
	_ = s.c.SetReadDeadline(deadline)
	n, err := s.c.Read(s.buf)
	return s.buf[:n], err
}

func (s *connSource) release() {
	s.pool.put(s.buf)
	s.buf = nil
}

// tunnelSource reads datagrams from a stack endpoint the way gonet does, but
// into a buffer that grows: the stack hands a datagram to any io.Writer, so
// a reassembled one that does not fit the small buffer is completed in a
// large one instead of being cut short.
type tunnelSource struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	entry  waiter.Entry
	notify chan struct{}
	small  []byte
	large  []byte // borrowed for one datagram
	n      int
}

func newTunnelSource(ep tcpip.Endpoint, wq *waiter.Queue) *tunnelSource {
	s := &tunnelSource{ep: ep, wq: wq, small: tunnelBufs.get()}
	s.entry, s.notify = waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&s.entry)
	return s
}

// Write collects one datagram; the stack calls it once per piece.
func (s *tunnelSource) Write(p []byte) (int, error) {
	if s.large == nil && s.n+len(p) > len(s.small) {
		if s.n+len(p) > maxDatagram {
			return 0, io.ErrShortWrite
		}
		s.large = largeBufs.get()
		copy(s.large, s.small[:s.n])
	}
	buf := s.small
	if s.large != nil {
		buf = s.large
	}
	if s.n+len(p) > len(buf) {
		return 0, io.ErrShortWrite
	}
	s.n += copy(buf[s.n:], p)
	return len(p), nil
}

func (s *tunnelSource) next(deadline time.Time) ([]byte, error) {
	if s.large != nil {
		largeBufs.put(s.large)
		s.large = nil
	}
	s.n = 0
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		_, err := s.ep.Read(s, tcpip.ReadOptions{})
		switch err.(type) {
		case nil:
			if s.large != nil {
				return s.large[:s.n], nil
			}
			return s.small[:s.n], nil
		case *tcpip.ErrWouldBlock:
			select {
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			case <-s.notify:
			}
		case *tcpip.ErrClosedForReceive:
			return nil, io.EOF
		default:
			return nil, errors.New(err.String())
		}
	}
}

func (s *tunnelSource) release() {
	s.wq.EventUnregister(&s.entry)
	tunnelBufs.put(s.small)
	s.small = nil
	if s.large != nil {
		largeBufs.put(s.large)
		s.large = nil
	}
}

// pump moves messages from src to dst until src ends or nothing moved for
// idle, then ends both sides of the flow so it does not linger half open
// until its idle limit. For datagrams every message is written as one, and
// an empty datagram is a message too.
func pump(src source, dst net.Conn, idle time.Duration, datagrams bool, end func()) (n int64) {
	defer end()
	defer src.release()
	for {
		msg, err := src.next(time.Now().Add(idle))
		if len(msg) > 0 || (datagrams && err == nil) {
			_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, werr := dst.Write(msg); werr != nil {
				return n
			}
			n += int64(len(msg))
		}
		if err != nil {
			return n
		}
	}
}

// relay copies a TCP connection both ways until either side ends or nothing
// moved for idle.
func relay(a, b net.Conn, idle time.Duration) (aToB, bToA int64) {
	var wg sync.WaitGroup
	end := func() { _ = a.Close(); _ = b.Close() }
	wg.Add(2)
	go func() { defer wg.Done(); aToB = pump(newConnSource(a, streamBufs), b, idle, false, end) }()
	go func() { defer wg.Done(); bToA = pump(newConnSource(b, streamBufs), a, idle, false, end) }()
	wg.Wait()
	return aToB, bToA
}

// relayUDP copies one UDP flow both ways: from the tunnel endpoint ep, whose
// datagrams client writes back, to the LAN socket out and back.
func relayUDP(client net.Conn, ep tcpip.Endpoint, wq *waiter.Queue, out net.Conn, idle time.Duration) (up, down int64) {
	var wg sync.WaitGroup
	end := func() { _ = client.Close(); _ = out.Close() }
	wg.Add(2)
	go func() { defer wg.Done(); up = pump(newTunnelSource(ep, wq), out, idle, true, end) }()
	go func() { defer wg.Done(); down = pump(newConnSource(out, largeBufs), client, idle, true, end) }()
	wg.Wait()
	return up, down
}

// reviewFlowsLocked closes the forwarded flows that the configuration just
// applied no longer allows: a route was removed, a guard changed (S30). A
// flow still waiting for its record is one of them: its admission finds it
// closed and refuses it.
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
