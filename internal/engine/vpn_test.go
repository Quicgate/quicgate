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
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", "10.77.0.1:80") },
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
