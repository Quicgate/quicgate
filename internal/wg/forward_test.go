package wg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// waitFor polls cond for up to five seconds.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// forwardFixture is a fixture with LAN access on, two devices that may reach
// 192.168.1.0/24, and a flow log the test controls. Nothing is dialled: the
// tests below drive the admission directly, with the stack instance the
// forwarder was installed for.
func forwardFixture(t *testing.T, record func(FlowRecord) bool) (*fixture, *instance) {
	t.Helper()
	f := newFixture(t)
	f.m.SetFlowLog(record)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	f.cfg.Forward = true
	phone, laptop := newDevice(t), newDevice(t)
	route := Route{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Proto: "any"}
	f.cfg.Devices = []Device{phone.device(7, "10.77.0.5", route), laptop.device(8, "10.77.0.6", route)}
	f.restart(t)
	f.m.mu.Lock()
	in := f.m.inst
	f.m.mu.Unlock()
	return f, in
}

// held reports how many flows and how many pending flows the peer has.
func held(m *Manager, key string) (flows, pending int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.flows[key]), m.pending[key]
}

// One device cannot take every half-open connection of the forwarder (L-33):
// its flows that are still being opened are capped, the one beyond the cap is
// refused, and another device is not held up by it.
func TestOnePeerCannotHoldEveryHalfOpenFlow(t *testing.T) {
	release := make(chan struct{})
	f, in := forwardFixture(t, func(r FlowRecord) bool {
		if r.Verdict == "allow" && r.Peer == "device:7" {
			<-release // the phone's records take their time
		}
		return true
	})
	src := netip.MustParseAddrPort("10.77.0.5:40000")
	results := make(chan admission, maxPendingPerPeer)
	for i := 0; i < maxPendingPerPeer; i++ {
		dst := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), uint16(1000+i))
		go func() { results <- f.m.admitFlow(in, "tcp", src, dst) }()
	}
	waitFor(t, "the pending flows to be counted", func() bool { _, n := held(f.m, "device:7"); return n == maxPendingPerPeer })

	began := time.Now()
	a := f.m.admitFlow(in, "tcp", src, netip.MustParseAddrPort("192.168.1.10:9999"))
	if a.t != nil || !strings.Contains(a.why, "being opened") {
		t.Fatalf("the flow beyond the cap was not refused: %+v", a)
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("the refusal took %v: it waited for the other flows", took)
	}
	other := netip.MustParseAddrPort("10.77.0.6:40000")
	b := f.m.admitFlow(in, "tcp", other, netip.MustParseAddrPort("192.168.1.10:80"))
	if b.t == nil {
		t.Fatalf("another device's flow was refused because of the first device's: %s", b.why)
	}
	f.m.endFlow(b, "tcp", other, netip.MustParseAddrPort("192.168.1.10:80"), time.Now(), 0, 0)

	close(release)
	for i := 0; i < maxPendingPerPeer; i++ {
		a := <-results
		if a.t == nil {
			t.Fatalf("a flow within the cap was refused: %s", a.why)
		}
		f.m.endFlow(a, "tcp", src, a.t.flow.dst, time.Now(), 0, 0)
	}
	if flows, pending := held(f.m, "device:7"); flows != 0 || pending != 0 {
		t.Fatalf("after the flows ended the device still holds %d flows and %d pending", flows, pending)
	}
}

// The record of an allowed flow is written with the endpoint's lock released
// (M-15): while a slow disk holds one admission, the endpoint keeps answering
// who a peer is, what its status is, and dials through sites.
func TestTheFlowLogIsNotWrittenUnderTheEndpointsLock(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	f, in := forwardFixture(t, func(r FlowRecord) bool {
		if r.Verdict == "allow" {
			entered <- struct{}{}
			<-release
		}
		return true
	})
	src, dst := netip.MustParseAddrPort("10.77.0.5:40000"), netip.MustParseAddrPort("192.168.1.10:80")
	res := make(chan admission, 1)
	go func() { res <- f.m.admitFlow(in, "tcp", src, dst) }()
	<-entered

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, ok := f.m.PeerOf(netip.MustParseAddr("10.77.0.6")); !ok {
			t.Error("the other device is not known while a record is written")
		}
		if st := f.m.DeviceStatus(); len(st) != 2 {
			t.Errorf("device status while a record is written = %+v", st)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7"); !errors.Is(err, ErrNoFallback) {
			t.Errorf("a dial through an unknown site while a record is written: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("the endpoint's lock was held while the flow record was written")
	}
	close(release)
	a := <-res
	if a.t == nil {
		t.Fatalf("the flow was refused: %s", a.why)
	}
	f.m.endFlow(a, "tcp", src, dst, time.Now(), 0, 0)
}

// A flow whose device is revoked, or whose route is taken away, while its
// record is being written does not come to be: the reservation made under the
// lock is closed by the revocation, the admission finds it closed, and the
// log shows the allow record followed by the refusal.
func TestARevocationDuringTheRecordWriteRefusesTheFlow(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	log := &flowLog{}
	f, in := forwardFixture(t, func(r FlowRecord) bool {
		log.record(r)
		if r.Verdict == "allow" {
			entered <- struct{}{}
			<-release
		}
		return true
	})
	src, dst := netip.MustParseAddrPort("10.77.0.5:40000"), netip.MustParseAddrPort("192.168.1.10:80")
	res := make(chan admission, 1)
	go func() { res <- f.m.admitFlow(in, "tcp", src, dst) }()
	<-entered
	if flows, pending := held(f.m, "device:7"); flows != 1 || pending != 1 {
		t.Fatalf("while the record is written the device holds %d flows and %d pending, want 1 and 1: the budget is not reserved", flows, pending)
	}

	// The phone is revoked while its record is being written.
	f.cfg.Devices = f.cfg.Devices[1:]
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	close(release)
	a := <-res
	if a.t != nil {
		t.Fatal("the flow of a device revoked during its admission was admitted")
	}
	if v := log.verdicts(dst.String()); len(v) != 2 || v[0] != "allow:" || !strings.HasPrefix(v[1], "deny:") {
		t.Fatalf("flow log = %v, want the allow record followed by the refusal", v)
	}
	if flows, pending := held(f.m, "device:7"); flows != 0 || pending != 0 {
		t.Fatalf("the revoked device still holds %d flows and %d pending", flows, pending)
	}
}

// Deny records are written at most denyRecordsPerSecond per peer; what is
// suppressed is counted (M-16).
func TestDenyRecordsAreRateLimitedPerPeer(t *testing.T) {
	m := New()
	now := time.Now()
	for i := 0; i < denyRecordsPerSecond; i++ {
		if !m.denyRecordAllowed("device:7", now) {
			t.Fatalf("deny record %d of the second was refused", i+1)
		}
	}
	if m.denyRecordAllowed("device:7", now) {
		t.Fatal("one deny record too many was allowed in the same second")
	}
	if !m.denyRecordAllowed("device:8", now) {
		t.Fatal("another peer's records are limited by the first peer's")
	}
	if !m.denyRecordAllowed("device:7", now.Add(time.Second)) {
		t.Fatal("the next second does not start afresh")
	}

	written := 0
	record := func(FlowRecord) bool { written++; return true }
	p := peer{key: "device:9", name: "phone9"}
	for i := 0; i < denyRecordsPerSecond+5; i++ {
		if a := m.refuse(record, FlowRecord{}, p, "no route"); a.t != nil || a.why != "no route" {
			t.Fatalf("refuse returned %+v", a)
		}
	}
	if written != denyRecordsPerSecond || m.FlowRecordsSuppressed() != 5 {
		t.Fatalf("%d deny records written and %d suppressed, want %d and 5", written, m.FlowRecordsSuppressed(), denyRecordsPerSecond)
	}
}

// A refused UDP flow is remembered by its 4-tuple for a while, so its next
// datagrams cost neither a decision nor a record; a reload forgets it, because
// the reload may have allowed it (M-16).
func TestARefusedUDPFlowIsRememberedUntilTheNextReload(t *testing.T) {
	m := New()
	k := flowKey{proto: "udp", src: netip.MustParseAddrPort("10.77.0.5:40000"), dst: netip.MustParseAddrPort("192.168.1.10:53")}
	now := time.Now()
	if m.recentlyDenied(k, now) {
		t.Fatal("a flow nobody refused is remembered as refused")
	}
	m.noteDenied(k, now)
	if !m.recentlyDenied(k, now.Add(denyCacheFor-time.Second)) {
		t.Fatal("a refused flow is not remembered")
	}
	other := k
	other.src = netip.MustParseAddrPort("10.77.0.5:40001")
	if m.recentlyDenied(other, now) {
		t.Fatal("another flow of the same device is taken for the refused one")
	}
	if m.recentlyDenied(k, now.Add(denyCacheFor+time.Second)) {
		t.Fatal("a refusal is remembered past its time")
	}
	m.noteDenied(k, now)
	m.forgetDenials()
	if m.recentlyDenied(k, now) {
		t.Fatal("a refusal survived a reload")
	}
}

// The forwarder for UDP, end to end: a device with a route reaches a service
// on the LAN and the flow relays both ways; a device without a route is
// refused once, and its further datagrams are dropped without another
// decision or record (M-16).
func TestUDPForwarderEndToEnd(t *testing.T) {
	lan := localLANAddr(t)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lan.AsSlice()})
	if err != nil {
		t.Skipf("cannot listen on %s: %v", lan, err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	target := netip.AddrPortFrom(lan, port)

	f := newFixture(t)
	log := &flowLog{}
	f.m.SetFlowLog(log.record)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	f.cfg.Forward = true
	allowed, other := newDevice(t), newDevice(t)
	route := Route{Prefix: netip.PrefixFrom(lan, 32), Proto: "udp", Ports: []PortRange{{port, port}}}
	f.cfg.Devices = []Device{allowed.device(1, "10.77.0.5", route), other.device(2, "10.77.0.6")}
	f.restart(t)
	allowed.start(t, f, "10.77.0.5")
	other.start(t, f, "10.77.0.6")

	c, err := allowed.net.DialUDPAddrPort(netip.AddrPort{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 1500)
	// The first datagrams cause the handshake and the admission; datagrams
	// that arrive while the admission is pending are dropped, so the device
	// asks again until an answer comes.
	answered := false
	for i := 0; i < 30 && !answered; i++ {
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := c.Read(buf); err == nil && string(buf[:n]) == "ping" {
			answered = true
		}
	}
	if !answered {
		t.Fatalf("a device with a route got no answer from the LAN; flow log: %+v; devices: %+v", log.records, f.m.DeviceStatus())
	}
	if v := log.verdicts(target.String()); len(v) == 0 || v[0] != "allow:" {
		t.Fatalf("flow log for the allowed flow = %v, want an allow record first", v)
	}
	// The flow stays: more datagrams go through the same endpoint, and no
	// second admission is recorded.
	for i := 0; i < 3; i++ {
		if _, err := c.Write([]byte("again")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "again" {
			t.Fatalf("datagram %d of the open flow: %q, %v", i, buf[:n], err)
		}
	}
	if n := log.count(func(r FlowRecord) bool { return r.Peer == "device:1" && r.Verdict == "allow" }); n != 1 {
		t.Fatalf("%d admission records for one flow", n)
	}

	// No route: refused, recorded once, and forgotten about after that.
	c2, err := other.net.DialUDPAddrPort(netip.AddrPort{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.Write([]byte("nope")); err != nil {
		t.Fatal(err)
	}
	denied := func(r FlowRecord) bool { return r.Peer == "device:2" && r.Verdict == "deny" }
	waitFor(t, "the refusal to be recorded", func() bool { return log.count(denied) >= 1 })
	for i := 0; i < 20; i++ {
		if _, err := c2.Write([]byte("nope")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := c2.Read(buf); err == nil {
		t.Fatalf("a device without a route got an answer: %q", buf[:n])
	}
	if n := log.count(denied); n != 1 {
		t.Fatalf("%d deny records for 21 datagrams of one refused flow, want 1: the refusal was not remembered", n)
	}
}

// A resolver that answers slowly delays the reload and the re-resolution
// that asked it, and nothing else: the endpoint keeps answering and dialling
// while the lookup runs (L-36).
func TestASlowResolverDoesNotStallTheEndpoint(t *testing.T) {
	f := newFixture(t)
	r := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	f.cfg.Sites = []Site{f.site(1, "office", r, "10.77.0.2", "192.168.50.0/24")}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	f.m.lookup = func(ctx context.Context, endpoint string) (string, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		return resolveEndpoint(ctx, endpoint)
	}
	// The endpoint stays available while a lookup is under way.
	available := func(during string) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			if st := f.m.Status(); len(st) != 1 {
				t.Errorf("status during %s = %+v", during, st)
			}
			if _, ok := f.m.PeerOf(netip.MustParseAddr("10.77.0.2")); !ok {
				t.Errorf("the site is unknown during %s", during)
			}
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatalf("the endpoint's lock was held while an endpoint name was resolved during %s", during)
		}
	}

	applied := make(chan error, 1)
	go func() { applied <- f.m.Apply(context.Background(), f.cfg) }()
	<-entered
	available("a reload")

	reresolved := make(chan struct{})
	go func() { f.m.Reresolve(context.Background()); close(reresolved) }()
	<-entered
	available("a re-resolution")

	close(release)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	<-reresolved
	if w := f.m.Status()[0].Warning; w != "" {
		t.Fatalf("the site carries a warning after the lookups finished: %q", w)
	}
}
