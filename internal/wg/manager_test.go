package wg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newKey(t testing.TB) (priv, pub string) {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// remoteSite is the far end of a tunnel: a plain WireGuard peer, as a router
// at a remote site would be, with an echo server on an address of its LAN.
type remoteSite struct {
	priv, pub, psk string
	dev            *device.Device
	net            *netstack.Net
	lan            netip.Addr
	port           int // the site's own UDP port, for sites quicgate can call
}

// startRemote brings up a peer that dials quicgate at serverPort (a dial-in
// site with keepalive, like one behind NAT) and serves echo on lan:7.
func startRemote(t testing.TB, serverPub string, serverPort int, tunnelAddr, lan netip.Addr, keepalive bool) *remoteSite {
	t.Helper()
	r := &remoteSite{lan: lan, port: freeUDPPort(t)}
	r.priv, r.pub = newKey(t)
	_, r.psk = newKey(t) // any 32 random bytes do as a preshared key
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{tunnelAddr, lan}, nil, mtu)
	if err != nil {
		t.Fatal(err)
	}
	r.net = tnet
	r.dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(r.dev.Close)
	privHex, _ := keyHex(r.priv)
	pubHex, _ := keyHex(serverPub)
	pskHex, _ := keyHex(r.psk)
	cfg := fmt.Sprintf("listen_port=%d\nprivate_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=10.77.0.1/32\nendpoint=127.0.0.1:%d\n", r.port, privHex, pubHex, pskHex, serverPort)
	if keepalive {
		cfg += "persistent_keepalive_interval=1\n"
	}
	if err := r.dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := r.dev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(lan, 7))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// An idle limit: when quicgate resets, its end of the connection
				// vanishes without a word, and this handler must not wait forever.
				buf := make([]byte, 4096)
				for {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return r
}

type fixture struct {
	m          *Manager
	cfg        Config
	serverPub  string
	serverPort int
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	priv, pub := newKey(t)
	f := &fixture{m: New(), serverPub: pub, serverPort: freeUDPPort(t)}
	f.m.logf = t.Logf
	f.cfg = Config{PrivateKey: priv, ListenPort: f.serverPort, Address: netip.MustParseAddr("10.77.0.1")}
	t.Cleanup(f.m.Close)
	// quicgate listens before any site comes up, as it does for real. It also
	// matters here: on Windows a UDP send to a closed port comes back as a
	// socket error that ends wireguard-go's receive loop for good.
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) site(id int64, name string, r *remoteSite, addr string, nets ...string) Site {
	// With an endpoint quicgate can start the handshake itself, so a site is
	// back at once after a reset. A site that only dials in returns when its
	// own no-reply timer fires, about 15 s later: see TestDialInSite.
	s := Site{ID: id, Name: name, PublicKey: r.pub, PresharedKey: r.psk, Address: netip.MustParseAddr(addr), Enabled: true,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", r.port)}
	for _, n := range nets {
		s.Networks = append(s.Networks, netip.MustParsePrefix(n))
	}
	return s
}

func echo(t testing.TB, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("echo through the tunnel = %q, %v", got, err)
	}
}

// An upstream behind a site is reached through the tunnel, and a first dial
// works although no handshake has happened yet: the dial causes it (S8, S9).
func TestDialInSite(t *testing.T) {
	f := newFixture(t)
	// The site dials in, like one behind NAT. quicgate has no endpoint for it
	// and dials at once anyway: the connection waits for the site's handshake
	// instead of being refused for the lack of one.
	r := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	dialIn := f.site(1, "office", r, "10.77.0.2", "192.168.50.0/24")
	dialIn.Endpoint = ""
	f.cfg.Sites = []Site{dialIn}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7")
	if err != nil {
		t.Fatalf("dial through the site: %v", err)
	}
	defer c.Close()
	echo(t, c, "hello through the tunnel")

	st := f.m.Status()
	if len(st) != 1 || !st[0].Up || st[0].Connections != 1 || st[0].RxBytes == 0 {
		t.Fatalf("status = %+v, want the site up with one connection and traffic", st)
	}
}

// Every refusal is final and marked: an address outside the site's networks,
// an unknown or disabled site, a stopped endpoint. None of them may be retried
// on the host network, where the same address can belong to another machine.
func TestRefusalsNeverFallBack(t *testing.T) {
	f := newFixture(t)
	r := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	off := f.site(2, "disabled", r, "10.77.0.3", "192.168.60.0/24")
	off.PublicKey, _ = func() (string, string) { _, p := newKey(t); return p, "" }()
	off.Enabled = false
	f.cfg.Sites = []Site{f.site(1, "office", r, "10.77.0.2", "192.168.50.0/24"), off}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7"); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("before the site is configured: %v, want ErrNoFallback", err)
	}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	// A listener on the host at the "same" address and port proves nothing
	// leaks: it must never see a connection.
	host, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	leaked := make(chan struct{}, 1)
	go func() {
		if c, err := host.Accept(); err == nil {
			c.Close()
			leaked <- struct{}{}
		}
	}()
	for name, tc := range map[string]struct {
		site int64
		addr string
	}{
		"outside the site's networks": {1, host.Addr().String()},
		"another private address":     {1, "192.168.51.10:7"},
		"unknown site":                {9, "192.168.50.10:7"},
		"disabled site":               {2, "192.168.60.10:7"},
		"port zero":                   {1, "192.168.50.10:0"},
	} {
		began := time.Now()
		c, err := f.m.DialContext(ctx, tc.site, "tcp", tc.addr)
		if !errors.Is(err, ErrNoFallback) {
			if c != nil {
				c.Close()
			}
			t.Errorf("%s: %v, want ErrNoFallback", name, err)
		}
		// Refused on inspection, before a packet is made: a refusal that only
		// arrives as a timeout means the traffic was sent into the tunnel.
		if took := time.Since(began); took > time.Second {
			t.Errorf("%s: refused after %v (%v): it was sent to the site first", name, took.Round(time.Millisecond), err)
		}
	}
	select {
	case <-leaked:
		t.Fatal("a refused dial reached the host network")
	case <-time.After(200 * time.Millisecond):
	}
	f.m.Close()
	if _, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7"); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("after Close: %v, want ErrNoFallback", err)
	}
}

// Removing or disabling a site ends the connections through it (S42).
func TestRemovingASiteClosesItsConnections(t *testing.T) {
	f := newFixture(t)
	r := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	f.cfg.Sites = []Site{f.site(1, "office", r, "10.77.0.2", "192.168.50.0/24")}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "before")

	f.cfg.Sites[0].Enabled = false
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	// Closed, not merely cut off: a connection whose peer is gone would also
	// stop answering, but only after a timeout, holding its resources and its
	// upstream request until then. The read must fail at once.
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	began := time.Now()
	_, err = c.Read(make([]byte, 5))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || time.Since(began) > time.Second {
		t.Fatalf("after its site was disabled the connection was not closed: read gave %v after %v", err, time.Since(began).Round(time.Millisecond))
	}
	if st := f.m.Status(); len(st) != 0 {
		t.Fatalf("status still lists the disabled site: %+v", st)
	}
	if _, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7"); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("dial to a disabled site: %v", err)
	}
	if r := f.m.Resets(); r != 0 {
		t.Fatalf("disabling a site caused %d resets, want none: nobody else took its addresses", r)
	}
}

// No address changes owner inside a running stack instance (S40): giving one
// site's network to another rebuilds the stack, also after the first site is
// gone; adding a network nobody owned does not.
func TestOwnershipChangeResetsTheStack(t *testing.T) {
	f := newFixture(t)
	a := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	b := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.3"), netip.MustParseAddr("192.168.50.10"), true)
	apply := func(sites ...Site) {
		t.Helper()
		f.cfg.Sites = sites
		if err := f.m.Apply(context.Background(), f.cfg); err != nil {
			t.Fatal(err)
		}
	}
	apply(f.site(1, "a", a, "10.77.0.2", "192.168.50.0/24"))
	apply(f.site(1, "a", a, "10.77.0.2", "192.168.50.0/24", "192.168.70.0/24"))
	if r := f.m.Resets(); r != 0 {
		t.Fatalf("adding a network nobody owned caused %d resets", r)
	}
	// Site a loses the network, then site b gets it: the stack has seen it
	// under a, so b may only have it in a new instance.
	apply(f.site(1, "a", a, "10.77.0.2", "192.168.70.0/24"))
	if r := f.m.Resets(); r != 0 {
		t.Fatalf("dropping a network caused %d resets", r)
	}
	apply(f.site(1, "a", a, "10.77.0.2", "192.168.70.0/24"), f.site(2, "b", b, "10.77.0.3", "192.168.50.0/24"))
	if r := f.m.Resets(); r != 1 {
		t.Fatalf("moving a network to another site caused %d resets, want 1", r)
	}
	// And the new owner works in the new instance.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := f.m.DialContext(ctx, 2, "tcp", "192.168.50.10:7")
	if err != nil {
		t.Fatalf("dial through the new owner: %v", err)
	}
	defer c.Close()
	echo(t, c, "new owner")
	// A subset also counts: /25 of what another site owned.
	apply(f.site(1, "a", a, "10.77.0.2", "192.168.70.0/24", "192.168.50.0/25"))
	if r := f.m.Resets(); r != 2 {
		t.Fatalf("an overlapping network caused %d resets in total, want 2", r)
	}
	// A new key for a site is a new peer.
	_, pub := newKey(t)
	s := f.site(1, "a", a, "10.77.0.2", "192.168.70.0/24", "192.168.50.0/25")
	s.PublicKey = pub
	apply(s)
	if r := f.m.Resets(); r != 3 {
		t.Fatalf("re-keying a site caused %d resets in total, want 3", r)
	}
}

// A controlled reset releases everything (spec Q4): the spike as a regression
// test, because a gVisor update could change it.
func TestResetsDoNotLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	if runtime.GOOS == "windows" {
		// During a reset quicgate's port is closed for a moment. On Windows a
		// UDP send to a closed port comes back as a socket error that ends
		// wireguard-go's receive loop in the remote peer for good, so the
		// remotes of this test stop answering at some cycle. Linux, where
		// quicgate runs and where CI runs this test, does not do that.
		t.Skip("wireguard-go's receive loop does not survive a closed peer port on Windows")
	}
	f := newFixture(t)
	a := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	b := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.3"), netip.MustParseAddr("192.168.50.10"), true)
	ctx := context.Background()
	cycle := func(i int) {
		// The network flips between the two sites: every Apply is a reset.
		owner, id, addr := a, int64(1), "10.77.0.2"
		if i%2 == 1 {
			owner, id, addr = b, 2, "10.77.0.3"
		}
		f.cfg.Sites = []Site{f.site(id, fmt.Sprint("s", id), owner, addr, "192.168.50.0/24")}
		if err := f.m.Apply(ctx, f.cfg); err != nil {
			t.Fatal(err)
		}
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := f.m.DialContext(dctx, id, "tcp", "192.168.50.10:7")
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		echo(t, c, "ping")
		// Left open on purpose: the reset has to clean it up.
	}
	settle := func() int {
		time.Sleep(3 * time.Second) // the remote's idle handlers end
		for i := 0; i < 5; i++ {
			runtime.GC()
			time.Sleep(100 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	cycle(0)
	cycle(1)
	base := settle()
	for i := 2; i < 22; i++ {
		cycle(i)
	}
	if got := settle(); got > base+8 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines grew from %d to %d over 20 resets\n%s", base, got, strings.SplitN(string(buf[:n]), "\n\n", 12)[0:10])
	}
	if r := f.m.Resets(); r < 20 {
		t.Fatalf("only %d resets happened, the test did not exercise them", r)
	}
}

func TestValidateSite(t *testing.T) {
	tunnel := netip.MustParsePrefix("10.77.0.0/24")
	_, serverPub := newKey(t)
	_, pubA := newKey(t)
	_, pubB := newKey(t)
	_, psk := newKey(t)
	own := []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24")}
	ok := Site{ID: 1, Name: "office", PublicKey: pubA, PresharedKey: psk, Address: netip.MustParseAddr("10.77.0.2"),
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}, Keepalive: 25, Enabled: true}
	other := Site{ID: 2, Name: "cabin", PublicKey: pubB, PresharedKey: psk, Address: netip.MustParseAddr("10.77.0.3"),
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.60.0/24")}}
	if err := ValidateSite(ok, tunnel, serverPub, []Site{other}, own, false); err != nil {
		t.Fatalf("a valid site was refused: %v", err)
	}
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	change := func(f func(*Site)) Site {
		s := ok
		s.Networks = append([]netip.Prefix(nil), ok.Networks...)
		f(&s)
		return s
	}
	for name, s := range map[string]Site{
		"the server's own key":    change(func(s *Site) { s.PublicKey = serverPub }),
		"another site's key":      change(func(s *Site) { s.PublicKey = pubB }),
		"the all-zero key":        change(func(s *Site) { s.PublicKey = zero }),
		"a malformed key":         change(func(s *Site) { s.PublicKey = "not-a-key" }),
		"no preshared key":        change(func(s *Site) { s.PresharedKey = "" }),
		"quicgate's own address":  change(func(s *Site) { s.Address = netip.MustParseAddr("10.77.0.1") }),
		"address outside tunnel":  change(func(s *Site) { s.Address = netip.MustParseAddr("10.78.0.2") }),
		"another site's address":  change(func(s *Site) { s.Address = netip.MustParseAddr("10.77.0.3") }),
		"no networks":             change(func(s *Site) { s.Networks = nil }),
		"overlaps the tunnel":     change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("10.77.0.0/16") }),
		"overlaps another site":   change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("192.168.60.128/25") }),
		"loopback":                change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("127.0.0.0/8") }),
		"link-local and metadata": change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("169.254.169.254/32") }),
		"multicast":               change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("224.0.0.0/24") }),
		"everything":              change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("0.0.0.0/0") }),
		"IPv6":                    change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("fd00::/64") }),
		"this machine's network":  change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("192.168.178.0/24") }),
		"duplicate name":          change(func(s *Site) { s.Name = "CABIN" }),
	} {
		if err := ValidateSite(s, tunnel, serverPub, []Site{other}, own, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	confirmed := change(func(s *Site) { s.Networks[0] = netip.MustParsePrefix("192.168.178.0/24") })
	if err := ValidateSite(confirmed, tunnel, serverPub, []Site{other}, own, true); err != nil {
		t.Errorf("this machine's network with the confirmation: %v", err)
	}
}

// An endpoint name that does not resolve is that site's problem alone: the
// endpoint keeps running, the other sites keep working, the site is listed
// with a warning, and it gets its endpoint once the name resolves.
func TestUnresolvableEndpointOnlyAffectsItsSite(t *testing.T) {
	f := newFixture(t)
	good := startRemote(t, f.serverPub, f.serverPort, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("192.168.50.10"), true)
	_, otherPub := newKey(t)
	_, otherPSK := newKey(t)
	broken := Site{ID: 2, Name: "cabin", PublicKey: otherPub, PresharedKey: otherPSK, Address: netip.MustParseAddr("10.77.0.3"),
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.60.0/24")}, Endpoint: "cabin.dyndns.invalid:51820", Enabled: true}
	resolves := false
	f.m.lookup = func(ctx context.Context, endpoint string) (string, error) {
		if strings.HasPrefix(endpoint, "cabin.") {
			if !resolves {
				return "", fmt.Errorf("endpoint %q does not resolve", endpoint)
			}
			return "203.0.113.7:51820", nil
		}
		return resolveEndpoint(ctx, endpoint)
	}
	f.cfg.Sites = []Site{f.site(1, "office", good, "10.77.0.2", "192.168.50.0/24"), broken}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatalf("one unresolvable endpoint took the whole endpoint down: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:7")
	if err != nil {
		t.Fatalf("the healthy site stopped working: %v", err)
	}
	defer c.Close()
	echo(t, c, "still fine")

	warning := func() string {
		for _, st := range f.m.Status() {
			if st.ID == 2 {
				return st.Warning
			}
		}
		t.Fatal("the site with the bad endpoint is not listed")
		return ""
	}
	if w := warning(); !strings.Contains(w, "does not resolve") {
		t.Fatalf("warning = %q, want it to say the endpoint does not resolve", w)
	}
	resolves = true
	f.m.Reresolve(context.Background())
	if w := warning(); w != "" {
		t.Fatalf("after the name resolved the warning stayed: %q", w)
	}
	dump, _ := f.m.inst.dev.IpcGet()
	if !strings.Contains(dump, "endpoint=203.0.113.7:51820") {
		t.Fatal("the site did not get its endpoint once the name resolved")
	}
	if r := f.m.Resets(); r != 0 {
		t.Fatalf("resolving an endpoint caused %d resets", r)
	}
}
