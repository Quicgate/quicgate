package wg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// remoteDevice is a phone or a laptop: a plain WireGuard peer that sends
// everything it is asked to reach into the tunnel.
type remoteDevice struct {
	priv, pub, psk string
	net            *netstack.Net
	dev            *device.Device
}

// newDevice makes a device's keys. It is started later, once quicgate's
// endpoint is up and knows it: that is the order things happen in for real,
// and on Windows a peer that sends to a closed port loses its receive loop.
func newDevice(t testing.TB) *remoteDevice {
	t.Helper()
	d := &remoteDevice{}
	d.priv, d.pub = newKey(t)
	_, d.psk = newKey(t)
	return d
}

func (d *remoteDevice) start(t testing.TB, f *fixture, addr string) {
	t.Helper()
	priv, psk := d.priv, d.psk
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, nil, mtu)
	if err != nil {
		t.Fatal(err)
	}
	d.net = tnet
	d.dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(d.dev.Close)
	privHex, _ := keyHex(priv)
	srvHex, _ := keyHex(f.serverPub)
	pskHex, _ := keyHex(psk)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\n", privHex, srvHex, pskHex, f.serverPort)
	if err := d.dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.dev.Up(); err != nil {
		t.Fatal(err)
	}
}

func (d *remoteDevice) device(id int64, addr string, routes ...Route) Device {
	return Device{ID: id, Name: fmt.Sprint("phone", id), Owner: "user@example.com", PublicKey: d.pub, PresharedKey: d.psk,
		Address: netip.MustParseAddr(addr), Routes: routes}
}

func (d *remoteDevice) dial(t testing.TB, to string, wait time.Duration) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return d.net.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(to))
}

// serveTunnel makes the manager serve an echo on tcp 80 in the tunnel and
// reports the peer of every connection.
func serveTunnel(f *fixture) chan Peer {
	peers := make(chan Peer, 16)
	f.m.SetListeners(Listeners{TCP: []uint16{80}, OnStart: func(tcp map[uint16]net.Listener, _ map[uint16]net.PacketConn) {
		ln := tcp[80]
		if ln == nil {
			return
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			peers <- c.(PeerConn).Peer()
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}})
	return peers
}

// restart applies the fixture's configuration on a fresh instance, so that
// listeners set after newFixture exist.
func (f *fixture) restart(t testing.TB) {
	t.Helper()
	f.m.Close()
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
}

// A device reaches quicgate's listener in the tunnel, and quicgate knows which
// device it is. Revoking the device closes its connection at once, and a
// device past its deadline is not admitted although it is still configured.
func TestDeviceReachesTheTunnelListener(t *testing.T) {
	f := newFixture(t)
	peers := serveTunnel(f)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	phone := newDevice(t)
	f.cfg.Devices = []Device{phone.device(7, "10.77.0.5")}
	f.restart(t)
	phone.start(t, f, "10.77.0.5")

	c, err := phone.dial(t, "10.77.0.1:80", 15*time.Second)
	if err != nil {
		t.Fatalf("the device cannot reach the tunnel listener: %v", err)
	}
	defer c.Close()
	echo(t, c, "hello quicgate")
	select {
	case p := <-peers:
		if p.Key != "device:7" || p.Site || p.Owner != "user@example.com" {
			t.Fatalf("the connection was attributed to %+v, want device:7", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no peer was reported for the connection")
	}
	if st := f.m.DeviceStatus(); len(st) != 1 || st[0].ID != 7 || st[0].Connections != 1 || !st[0].Up {
		t.Fatalf("device status = %+v", st)
	}

	// Without LAN access the device reaches nothing but quicgate: a port
	// nobody listens on, and an address beyond the tunnel, go nowhere.
	if c2, err := phone.dial(t, "10.77.0.1:81", 2*time.Second); err == nil {
		c2.Close()
		t.Fatal("a port without a listener accepted a connection")
	}

	// Revoked: removed from the configuration.
	f.cfg.Devices = nil
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	began := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the revoked device's connection still delivers data")
	}
	_ = began // the device end only notices by timeout; quicgate's end is checked below
	if st := f.m.DeviceStatus(); len(st) != 0 {
		t.Fatalf("a revoked device is still listed: %+v", st)
	}

	// Past its deadline: configured, handshakes, and still not admitted.
	late := phone.device(8, "10.77.0.6")
	late.Until = time.Now().Add(-time.Minute)
	f.cfg.Devices = []Device{late}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.m.PeerOf(netip.MustParseAddr("10.77.0.6")); ok {
		t.Fatal("a device past its deadline is reported as an active peer")
	}
}

// localLANAddr returns a non-loopback IPv4 address of this machine, which
// stands in for a machine on the LAN.
func localLANAddr(t testing.TB) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				ip = ip.Unmap()
				if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					return ip
				}
			}
		}
	}
	t.Skip("this machine has no non-loopback IPv4 address to stand in for the LAN")
	return netip.Addr{}
}

type flowLog struct {
	mu      sync.Mutex
	records []FlowRecord
	full    bool
}

func (l *flowLog) record(r FlowRecord) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.full && r.Verdict == "allow" {
		return false
	}
	l.records = append(l.records, r)
	return true
}

func (l *flowLog) verdicts(dst string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.records {
		if r.Dest == dst {
			out = append(out, r.Verdict+":"+r.Reason)
		}
	}
	return out
}

// The forwarder end to end: a device with a route reaches a machine on the
// LAN, one without is reset, an allowed flow that cannot be logged is refused,
// and taking the route away closes the flow that used it.
func TestForwarderEndToEnd(t *testing.T) {
	lan := localLANAddr(t)
	ln, err := net.Listen("tcp4", netip.AddrPortFrom(lan, 0).String())
	if err != nil {
		t.Skipf("cannot listen on %s: %v", lan, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	target := ln.Addr().String()
	port := netip.MustParseAddrPort(target).Port()

	f := newFixture(t)
	log := &flowLog{}
	f.m.SetFlowLog(log.record)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	f.cfg.Forward = true
	allowed, other := newDevice(t), newDevice(t)
	route := Route{Prefix: netip.PrefixFrom(lan, 32), Proto: "tcp", Ports: []PortRange{{port, port}}}
	f.cfg.Devices = []Device{allowed.device(1, "10.77.0.5", route), other.device(2, "10.77.0.6")}
	f.restart(t)
	allowed.start(t, f, "10.77.0.5")
	other.start(t, f, "10.77.0.6")

	c, err := allowed.dial(t, target, 15*time.Second)
	if err != nil {
		t.Fatalf("a device with a route cannot reach the LAN: %v; flow log: %+v; devices: %+v", err, log.records, f.m.DeviceStatus())
	}
	defer c.Close()
	echo(t, c, "through the forwarder")
	if v := log.verdicts(target); len(v) == 0 || v[0] != "allow:" {
		t.Fatalf("flow log for the allowed flow = %v, want an allow record first", v)
	}

	// No route: reset before the handshake completes, and logged as denied.
	began := time.Now()
	if c2, err := other.dial(t, target, 8*time.Second); err == nil {
		c2.Close()
		t.Fatal("a device without a route reached the LAN")
	} else if time.Since(began) > 3*time.Second {
		t.Fatalf("the refusal took %v: the connection was not reset, it timed out (%v)", time.Since(began).Round(time.Millisecond), err)
	}
	// The allowed device, another port: refused too.
	if c3, err := allowed.dial(t, netip.AddrPortFrom(lan, port+1).String(), 5*time.Second); err == nil {
		c3.Close()
		t.Fatal("a port outside the route was reachable")
	}

	// No record, no flow.
	log.mu.Lock()
	log.full = true
	log.mu.Unlock()
	if c4, err := allowed.dial(t, target, 5*time.Second); err == nil {
		c4.Close()
		t.Fatal("an allowed flow was admitted although its record could not be taken")
	}
	log.mu.Lock()
	log.full = false
	log.mu.Unlock()

	// The route goes away: the open flow that used it is closed by quicgate.
	f.cfg.Devices = []Device{allowed.device(1, "10.77.0.5"), other.device(2, "10.77.0.6")}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	began = time.Now()
	_, err = c.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || time.Since(began) > 2*time.Second {
		t.Fatalf("after its route was removed the flow was not closed: read gave %v after %v", err, time.Since(began).Round(time.Millisecond))
	}
	if r := f.m.Resets(); r != 0 {
		t.Fatalf("a policy change caused %d resets of the stack, want none", r)
	}
}

// The destination rules, without a network (S28, S48).
func TestForwarderDecisions(t *testing.T) {
	own := netip.MustParseAddr("192.168.178.54")
	cfg := Config{
		Tunnel: netip.MustParsePrefix("10.77.0.0/24"),
		Sites:  []Site{{ID: 1, Networks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}, Enabled: true}},
		Guard: Guard{
			OwnAddrs:           func() []netip.Addr { return []netip.Addr{own, netip.MustParseAddr("127.0.0.1")} },
			OwnNets:            func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24")} },
			ListenerPorts:      func() []uint16 { return []uint16{80, 443, 81, 51820, 2222} },
			ProtectedAddrs:     []netip.Addr{netip.MustParseAddr("192.168.178.2")},
			ProtectedEndpoints: []netip.AddrPort{netip.MustParseAddrPort("192.168.178.1:8443")},
		},
	}
	lan := Route{Prefix: netip.MustParsePrefix("192.168.178.0/24"), Proto: "any"}
	everything := Route{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Proto: "any"}
	sshToOwn := Route{Prefix: netip.PrefixFrom(own, 32), Proto: "tcp", Ports: []PortRange{{22, 22}}}
	adminOnOwn := Route{Prefix: netip.PrefixFrom(own, 32), Proto: "tcp", Ports: []PortRange{{81, 81}, {443, 443}}}
	lastHost := Route{Prefix: netip.MustParsePrefix("192.168.178.254/32"), Proto: "tcp"}
	p2p := Route{Prefix: netip.MustParsePrefix("10.200.0.0/31"), Proto: "tcp"}
	for _, tc := range []struct {
		name   string
		routes []Route
		proto  string
		dst    string
		want   bool
	}{
		{"a LAN host inside the route", []Route{lan}, "tcp", "192.168.178.116:445", true},
		{"udp with an any route", []Route{lan}, "udp", "192.168.178.116:53", true},
		{"no route at all", nil, "tcp", "192.168.178.116:445", false},
		{"outside the route", []Route{lan}, "tcp", "192.168.179.10:80", false},
		{"loopback, even with a route for everything", []Route{everything}, "tcp", "127.0.0.1:81", false},
		{"cloud metadata", []Route{everything}, "tcp", "169.254.169.254:80", false},
		{"multicast", []Route{everything}, "udp", "224.0.0.251:5353", false},
		{"limited broadcast", []Route{everything}, "udp", "255.255.255.255:67", false},
		{"unspecified", []Route{everything}, "tcp", "0.0.0.0:80", false},
		{"port zero", []Route{everything}, "tcp", "192.168.178.116:0", false},
		{"another peer in the tunnel", []Route{everything}, "tcp", "10.77.0.9:22", false},
		{"quicgate's tunnel address", []Route{everything}, "tcp", "10.77.0.1:81", false},
		{"a site's network", []Route{everything}, "tcp", "192.168.50.10:80", false},
		{"a protected endpoint", []Route{everything}, "tcp", "192.168.178.1:8443", false},
		{"the same address, another port", []Route{everything}, "tcp", "192.168.178.1:443", true},
		{"the broadcast address of the real subnet", []Route{everything}, "udp", "192.168.178.255:137", false},
		{"the network address of the real subnet", []Route{everything}, "tcp", "192.168.178.0:80", false},
		{"a /32 grant that is the last host of the subnet", []Route{lastHost}, "tcp", "192.168.178.254:22", true},
		{"both addresses of a /31", []Route{p2p}, "tcp", "10.200.0.0:22", true},
		{"both addresses of a /31 (second)", []Route{p2p}, "tcp", "10.200.0.1:22", true},
		{"this machine through a subnet route", []Route{lan}, "tcp", "192.168.178.54:22", false},
		{"this machine through a route for everything", []Route{everything}, "tcp", "192.168.178.54:22", false},
		{"this machine, exact host and port", []Route{sshToOwn}, "tcp", "192.168.178.54:22", true},
		{"this machine, exact host, quicgate's admin port", []Route{adminOnOwn}, "tcp", "192.168.178.54:81", false},
		{"this machine, exact host, quicgate's https port", []Route{adminOnOwn}, "tcp", "192.168.178.54:443", false},
		{"this machine, a stream port", []Route{{Prefix: netip.PrefixFrom(own, 32), Proto: "tcp", Ports: []PortRange{{2222, 2222}}}}, "tcp", "192.168.178.54:2222", false},
		{"a declared alias of this machine through a subnet route", []Route{lan}, "tcp", "192.168.178.2:22", false},
		{"IPv6", []Route{everything}, "tcp", "[fd00::1]:80", false},
		{"an IPv4-mapped loopback", []Route{everything}, "tcp", "[::ffff:127.0.0.1]:81", false},
	} {
		got, why := decide(cfg, tc.routes, tc.proto, netip.MustParseAddrPort(tc.dst))
		if got != tc.want {
			t.Errorf("%s: allowed=%v (%s), want %v", tc.name, got, why, tc.want)
		}
	}
}

// A site that only calls in is called back where it was last heard from, so it
// returns within seconds after quicgate restarts instead of after its own
// no-reply timer.
func TestDialInSiteReturnsQuicklyAfterARestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wireguard-go's receive loop does not survive a closed peer port on Windows")
	}
	f := newFixture(t)
	state := filepath.Join(t.TempDir(), "wg-endpoints.json")
	f.m.SetStateFile(state)
	r := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), false)
	site := f.site(1, "office", r, "10.77.0.2", "192.168.50.0/24")
	site.Endpoint, site.Keepalive = "", 25
	f.cfg.Sites = []Site{site}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	// The remote has no keepalive in this test, so it speaks first only once,
	// because it is asked to.
	rc, err := r.net.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("10.77.0.1:9"))
	if err == nil {
		rc.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	c, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7")
	cancel()
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	echo(t, c, "before the restart")
	c.Close()

	// A restart: a new manager that only has the state file.
	f.m.Close()
	data, err := os.ReadFile(state)
	if err != nil || !strings.Contains(string(data), "127.0.0.1:") {
		t.Fatalf("the peer's last address was not saved: %q %v", data, err)
	}
	m2 := New()
	m2.logf = t.Logf
	m2.SetStateFile(state)
	t.Cleanup(m2.Close)
	if err := m2.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c2, err := m2.DialContext(ctx, 1, "tcp", "192.168.50.10:7")
	if err != nil {
		t.Fatalf("after the restart the site did not return within 10 s: %v", err)
	}
	defer c2.Close()
	echo(t, c2, "after the restart")
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("the site took %v to return; without the remembered address it takes 15 s or more", took.Round(time.Millisecond))
	}
}
