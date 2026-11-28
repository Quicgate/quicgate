package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// tunnelClient is a phone: a plain WireGuard peer with a web client that
// sends everything into the tunnel.
type tunnelClient struct {
	priv       []byte
	pub, psk   string
	net        *netstack.Net
	httpClient *http.Client
}

func newTunnelClient(t *testing.T) *tunnelClient {
	t.Helper()
	var k [32]byte
	_, _ = rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wg.NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return &tunnelClient{priv: k[:], pub: base64.StdEncoding.EncodeToString(pub), psk: psk}
}

// start brings the device up. quicgate must be listening and know the device
// already, as it does for real.
func (c *tunnelClient) start(t *testing.T, addr, serverPub string, serverPort int) {
	t.Helper()
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(c.priv), b64hex(t, serverPub), b64hex(t, c.psk), serverPort)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	c.net = tnet
	c.httpClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", "10.77.0.1:80")
		},
		DisableKeepAlives: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// get asks quicgate, inside the tunnel, for a host.
func (c *tunnelClient) get(host string) (int, string, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// The private entrance, end to end: a device in a real tunnel reaches
// quicgate's hosts, is matched by VPN rules and never by address rules, sees
// VPN-only hosts that the public side does not, resolves quicgate's names to
// the tunnel, is never banned, and is cut off when it is revoked.
func TestPrivateEntrance(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	t.Cleanup(e.wg.Close)
	port := freeUDP(t)
	setSettings(t, st, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(port)})
	reload(t, e)
	serverPub := e.WGStatus().PublicKey

	phone := newTunnelClient(t)
	_, network, _, _ := WGSettings(st)
	dev := store.WGDevice{Name: "phone", Kind: "admin", PublicKey: phone.pub, Enabled: true}
	if err := st.CreateWGDevice(&dev, network, phone.psk, 0); err != nil {
		t.Fatal(err)
	}
	if dev.Address != "10.77.0.2" {
		t.Fatalf("the first device got %s, want 10.77.0.2", dev.Address)
	}
	// The same key again, also after a revocation, is refused: a key is one peer.
	again := store.WGDevice{Name: "clone", Kind: "admin", PublicKey: phone.pub, Enabled: true}
	if err := st.CreateWGDevice(&again, network, phone.psk, 0); err == nil {
		t.Fatal("a second device with the same public key was stored")
	}

	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("served " + r.Host)) })
	lan := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all", Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	vpn := mustCreateACL(t, st, &store.AccessList{Name: "vpn", Satisfy: "all", Rules: []store.AccessRule{{Action: "allow", VPN: &store.VPNSubject{Kind: "device"}}}})
	sites := mustCreateACL(t, st, &store.AccessList{Name: "sites", Satisfy: "all", Rules: []store.AccessRule{{Action: "allow", VPN: &store.VPNSubject{Kind: "site"}}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"open.test"}, Upstream: up})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"lan.test"}, Upstream: up, AccessListID: &lan})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"vpn.test"}, Upstream: up, AccessListID: &vpn})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"sites.test"}, Upstream: up, AccessListID: &sites})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"only.test"}, Upstream: up, Options: store.Options{VPNOnly: true}})
	reload(t, e)
	e.banCfg.Store(&banConfig{enabled: true, threshold: 1, window: time.Hour, banFor: time.Hour})
	phone.start(t, dev.Address, serverPub, port)

	eventually(t, "the device to reach quicgate in the tunnel", func() bool {
		code, _, err := phone.get("open.test")
		return err == nil && code == http.StatusOK
	})
	for host, want := range map[string]int{
		"open.test":  http.StatusOK,        // no list: public, so peers too
		"vpn.test":   http.StatusOK,        // a VPN rule about devices
		"only.test":  http.StatusOK,        // VPN-only host
		"lan.test":   http.StatusForbidden, // 10.77.0.2 is in 10.0.0.0/8, and an address rule still never admits a peer
		"sites.test": http.StatusForbidden, // a rule about sites does not name a device
	} {
		code, body, err := phone.get(host)
		if err != nil || code != want {
			t.Errorf("in the tunnel, %s: %d %q %v, want %d", host, code, body, err, want)
		}
	}
	// Refusals in the tunnel never ban (the threshold is one).
	if bans := e.Bans(); len(bans) != 0 {
		t.Fatalf("a refusal in the tunnel caused a ban: %+v", bans)
	}

	// The public side. An address in the tunnel prefix proves nothing there.
	for _, tc := range []struct {
		host, from string
		want       int
	}{
		{"vpn.test", "203.0.113.9", http.StatusForbidden},
		{"vpn.test", "10.77.0.2", http.StatusForbidden}, // the device's own tunnel address, from outside the tunnel
		{"lan.test", "10.77.0.2", http.StatusOK},        // an ordinary request that an ordinary CIDR rule admits
		{"open.test", "203.0.113.9", http.StatusOK},
	} {
		if rr := req(e, http.MethodGet, tc.host, "/", tc.from, nil); rr.Code != tc.want {
			t.Errorf("from outside, %s as %s: %d, want %d", tc.host, tc.from, rr.Code, tc.want)
		}
	}
	unknown := req(e, http.MethodGet, "nothing.test", "/", "203.0.113.9", nil)
	hidden := req(e, http.MethodGet, "only.test", "/", "203.0.113.9", nil)
	if hidden.Code != unknown.Code || hidden.Body.String() != unknown.Body.String() {
		t.Fatalf("a VPN-only host answers the public side with %d %q, an unknown host with %d %q: they must be the same",
			hidden.Code, hidden.Body.String(), unknown.Code, unknown.Body.String())
	}

	// Tunnel DNS: quicgate's names point into the tunnel.
	ask := func(name string, typ dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 4242, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
		packed, _ := q.Pack()
		c, err := phone.net.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.77.0.1:53"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(packed); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("no DNS answer for %s: %v", name, err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		return m
	}
	a := ask("vpn.test.", dnsmessage.TypeA)
	if len(a.Answers) != 1 || a.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 77, 0, 1} || !a.Authoritative || a.AuthenticData {
		t.Fatalf("A vpn.test = %+v, want 10.77.0.1, authoritative, not authenticated data", a)
	}
	if aaaa := ask("vpn.test.", dnsmessage.TypeAAAA); len(aaaa.Answers) != 0 || aaaa.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA vpn.test = %+v, want no data", aaaa)
	}

	// Revoked: gone from the endpoint, and its key can never come back.
	if err := st.RevokeWGDevice(dev.ID, nil); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	if _, _, err := phone.get("open.test"); err == nil {
		t.Fatal("a revoked device still gets answers in the tunnel")
	}
	back := store.WGDevice{Name: "back", Kind: "admin", PublicKey: phone.pub, Enabled: true}
	if err := st.CreateWGDevice(&back, network, phone.psk, 0); err == nil {
		t.Fatal("a revoked device's key was registered again")
	}
}

// A relayed reply has to repeat the question it answers (S20).
func TestDNSReplyMustRepeatTheQuestion(t *testing.T) {
	msg := func(name string, response bool) []byte {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: response},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		b, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	query := msg("app.example.com.", false)
	if !sameQuestion(query, msg("APP.example.com.", true)) {
		t.Error("a reply to the same name in another case was refused")
	}
	if sameQuestion(query, msg("evil.example.com.", true)) {
		t.Error("a reply about another name was taken for the answer")
	}
	if sameQuestion(query, []byte{0, 7, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("a reply without a question was taken for the answer")
	}
}

// A device keeps the address it was given. The API refuses to move the tunnel
// network while devices exist, but should the setting change by other means,
// a device whose address lies outside the network is left out of the
// endpoint's configuration rather than given an AllowedIPs outside the tunnel
// (L-34).
func TestADeviceOutsideTheTunnelNetworkIsLeftOut(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	_, network, _, err := WGSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	dev := store.WGDevice{Name: "phone", Kind: "admin", PublicKey: newTunnelClient(t).pub, Enabled: true}
	psk, err := wg.NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWGDevice(&dev, network, psk, 0); err != nil {
		t.Fatal(err)
	}
	if devs, _ := e.wgDevices(time.Now(), false); len(devs) != 1 || devs[0].Address.String() != dev.Address {
		t.Fatalf("devices in the network they were made in = %+v, want the one device", devs)
	}
	setSettings(t, st, map[string]string{"wg_network": "10.88.0.0/24"})
	if devs, _ := e.wgDevices(time.Now(), false); len(devs) != 0 {
		t.Fatalf("a device at %s is configured although the tunnel network is 10.88.0.0/24 now: %+v", dev.Address, devs)
	}
}

// A device the admin adds can carry addresses on the local network of its
// own. They count only while local network access is on, an end date that
// has passed takes the whole device off, a device without addresses of its
// own gets none from anybody's rule, and a device from before the two kinds
// were one (kind "breakglass") behaves exactly the same.
func TestAnAdminDeviceCarriesItsOwnLocalAddresses(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	_, network, _, err := WGSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	// A rule for people must never spill over to a device nobody logged in on.
	idp := &store.OIDCProvider{Name: "idp", Issuer: "https://idp.example.com", ClientID: "c", ClientSecret: "s"}
	if err := st.CreateOIDCProvider(idp); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveVPNPolicy(&store.VPNPolicy{Name: "everybody", Subject: store.VPNSubject{Kind: "any-user", Provider: idp.ID},
		Routes: []store.VPNRoute{{CIDR: "192.168.9.0/24", Proto: "any"}}}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	nas := []store.VPNRoute{{Name: "NAS", CIDR: "192.168.1.10/32", Proto: "tcp", Ports: "445"}}
	make := func(name, kind string, routes []store.VPNRoute, expires string) store.WGDevice {
		d := store.WGDevice{Name: name, Kind: kind, PublicKey: newTunnelClient(t).pub, Enabled: true, Routes: routes, ExpiresAt: expires}
		psk, err := wg.NewPresharedKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CreateWGDevice(&d, network, psk, 0); err != nil {
			t.Fatal(err)
		}
		return d
	}
	plain := make("plain", "admin", nil, "")
	phone := make("phone", "admin", nas, until)
	old := make("old", "breakglass", nas, until)

	byID := func(now time.Time, lan bool) map[int64]wg.Device {
		devs, owners := e.wgDevices(now, lan)
		if len(owners) != 0 {
			t.Fatalf("an admin's device has an owner at an identity provider: %+v", owners)
		}
		out := map[int64]wg.Device{}
		for _, d := range devs {
			out[d.ID] = d
		}
		return out
	}
	// Local network access off: every device is there, none has a route.
	off := byID(time.Now(), false)
	for _, d := range []store.WGDevice{plain, phone, old} {
		got, ok := off[d.ID]
		if !ok || len(got.Routes) != 0 {
			t.Fatalf("with local network access off, device %q = %+v (present %v), want it present without routes", d.Name, got, ok)
		}
	}
	// On: the two devices with addresses get exactly theirs, the plain one none.
	on := byID(time.Now(), true)
	if got := on[plain.ID]; len(got.Routes) != 0 {
		t.Fatalf("a device without addresses of its own got routes: %+v", got.Routes)
	}
	for _, d := range []store.WGDevice{phone, old} {
		got := on[d.ID]
		if len(got.Routes) != 1 || got.Routes[0].Prefix.String() != "192.168.1.10/32" || got.Routes[0].Proto != "tcp" ||
			len(got.Routes[0].Ports) != 1 || got.Routes[0].Ports[0].From != 445 || got.Routes[0].Ports[0].To != 445 {
			t.Fatalf("device %q routes = %+v, want tcp 192.168.1.10/32 port 445 and nothing else", d.Name, got.Routes)
		}
		if got.Until.IsZero() {
			t.Fatalf("device %q has no deadline although it has an end date", d.Name)
		}
	}
	// Past the end date both are gone, routes and all; the plain one stays.
	late := byID(time.Now().Add(2*time.Hour), true)
	if _, ok := late[plain.ID]; !ok {
		t.Fatal("the device without an end date is gone")
	}
	for _, d := range []store.WGDevice{phone, old} {
		if got, ok := late[d.ID]; ok {
			t.Fatalf("device %q is still configured after its end date: %+v", d.Name, got)
		}
	}
	// What such a device carries never opens what is protected: quicgate's
	// own listeners stay out of reach, whatever its routes say.
	wide := []store.VPNRoute{{CIDR: "127.0.0.0/8", Proto: "any"}}
	if err := wide[0].Validate(); err == nil {
		t.Fatal("loopback was accepted as a route")
	}
	setSettings(t, st, map[string]string{"wg_protected_endpoints": "192.168.1.2"})
	if answer, err := e.ExplainRoute([]store.VPNRoute{{CIDR: "192.168.1.0/24", Proto: "any"}}, "tcp", "192.168.1.2:22"); err != nil || !strings.HasPrefix(answer, "refused") {
		t.Fatalf("a protected endpoint under a whole-network route: %q %v, want refused", answer, err)
	}
	if answer, err := e.ExplainRoute(nas, "tcp", "192.168.1.10:22"); err != nil || !strings.HasPrefix(answer, "refused") {
		t.Fatalf("a port the route does not name: %q %v, want refused", answer, err)
	}
	if answer, err := e.ExplainRoute(nas, "tcp", "192.168.1.10:445"); err != nil || !strings.HasPrefix(answer, "allowed") {
		t.Fatalf("the named address and port: %q %v, want allowed", answer, err)
	}
}

// The form for switching the VPN on has a field for the addresses used
// inside it, and leaving that field empty means "the usual ones". An empty
// setting must not stop the VPN from starting.
func TestAnEmptyTunnelNetworkSettingMeansTheDefault(t *testing.T) {
	_, st := newTestEngine(t)
	setSettings(t, st, map[string]string{"wg_network": ""})
	_, network, _, err := WGSettings(st)
	if err != nil || network.String() != wgDefaultNetwork {
		t.Fatalf("network = %v, err = %v, want %s", network, err, wgDefaultNetwork)
	}
	setSettings(t, st, map[string]string{"wg_network": "not a network"})
	if _, _, _, err := WGSettings(st); err == nil {
		t.Fatal("a network that is not one was accepted")
	}
}

// When a device was last seen is kept in the database, so that it is still
// known after a restart. It is written when the time has really moved, and
// not more often than once a minute per device.
func TestDeviceLastSeenIsRememberedAcrossRestarts(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	_, network, _, err := WGSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string) store.WGDevice {
		d := store.WGDevice{Name: name, Kind: "admin", PublicKey: newTunnelClient(t).pub, Enabled: true}
		psk, err := wg.NewPresharedKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CreateWGDevice(&d, network, psk, 0); err != nil {
			t.Fatal(err)
		}
		return d
	}
	phone, laptop := mk("phone"), mk("laptop")
	t0 := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	seen := func(id int64) string { d, _ := st.GetWGDevice(id); return d.LastSeenAt }
	status := func(ts time.Time) []wg.PeerStatus {
		return []wg.PeerStatus{{ID: phone.ID, LastHandshake: ts}, {ID: laptop.ID}}
	}

	if n := e.rememberSeen(status(t0)); n != 1 || seen(phone.ID) != "2026-11-28T10:00:00Z" {
		t.Fatalf("first contact: %d writes, stored %q", n, seen(phone.ID))
	}
	if seen(laptop.ID) != "" {
		t.Fatalf("a device that was never seen has a time: %q", seen(laptop.ID))
	}
	// The same handshake again, and one a few seconds later: nothing to write.
	if n := e.rememberSeen(status(t0)); n != 0 {
		t.Fatalf("the same handshake was written again: %d writes", n)
	}
	if n := e.rememberSeen(status(t0.Add(20 * time.Second))); n != 0 || seen(phone.ID) != "2026-11-28T10:00:00Z" {
		t.Fatalf("a handshake 20 s later: %d writes, stored %q, want none within a minute", n, seen(phone.ID))
	}
	if n := e.rememberSeen(status(t0.Add(2 * time.Minute))); n != 1 || seen(phone.ID) != "2026-11-28T10:02:00Z" {
		t.Fatalf("two minutes later: %d writes, stored %q", n, seen(phone.ID))
	}
	// A restart: a new engine on the same database knows it still, and an
	// engine that has seen nothing yet does not wipe it.
	e2 := New(Config{DisableTLS: true, DataDir: t.TempDir()}, st)
	t.Cleanup(func() { _ = e2.accessLog.Close(); _ = e2.ban.closePersist() })
	if n := e2.rememberSeen([]wg.PeerStatus{{ID: phone.ID}, {ID: laptop.ID}}); n != 0 || seen(phone.ID) != "2026-11-28T10:02:00Z" {
		t.Fatalf("after a restart: %d writes, stored %q", n, seen(phone.ID))
	}
	if d, _ := st.GetWGDevice(phone.ID); d.FirstSeenAt != "2026-11-28T10:00:00Z" {
		t.Fatalf("first seen = %q", d.FirstSeenAt)
	}
}
