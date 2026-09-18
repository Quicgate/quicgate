package engine

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func b64hex(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// remoteSiteHTTP is a remote site: a plain WireGuard peer with a web server on
// an address of its own LAN, 192.168.50.10:80.
type remoteSiteHTTP struct {
	pub, psk string
	port     int
	hits     chan string // the Host header of every request that arrives
}

func startRemoteSiteHTTP(t *testing.T, serverPub string, serverPort int) *remoteSiteHTTP {
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
	r := &remoteSiteHTTP{pub: base64.StdEncoding.EncodeToString(pub), psk: psk, port: freeUDP(t), hits: make(chan string, 16)}
	lan := netip.MustParseAddr("192.168.50.10")
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2"), lan}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("listen_port=%d\nprivate_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=10.77.0.1/32\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\n",
		r.port, hex.EncodeToString(k[:]), b64hex(t, serverPub), b64hex(t, psk), serverPort)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(lan, 80))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case r.hits <- req.Host:
		default:
		}
		_, _ = w.Write([]byte("from the site"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return r
}

func setSettings(t *testing.T, st *store.Store, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
}

// eventually retries a request while the tunnel shakes hands.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A host whose upstream names a site is proxied through the tunnel, end to
// end. When the tunnel is switched off the host answers 502: the upstream's
// address is never tried on the host network, and it works again when the
// tunnel returns.
func TestHostThroughWireGuardSite(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	e, st := newTestEngine(t)
	t.Cleanup(e.wg.Close)
	port := freeUDP(t)
	setSettings(t, st, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(port)})
	reload(t, e)
	status := e.WGStatus()
	if !status.Running || status.PublicKey == "" || status.Address != "10.77.0.1" {
		t.Fatalf("endpoint after enabling = %+v", status)
	}
	if raw := rawSetting(t, e, "wg_private_key"); !strings.HasPrefix(raw, "qgs1.") {
		t.Fatalf("the server key is stored as %.12q, want a sealed value", raw)
	}

	remote := startRemoteSiteHTTP(t, status.PublicKey, port)
	site := store.WGSite{Name: "office", PublicKey: remote.pub, Networks: []string{"192.168.50.0/24"},
		Endpoint: fmt.Sprintf("127.0.0.1:%d", remote.port), Keepalive: 25, Enabled: true}
	_, network, _, err := WGSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWGSite(&site, network, remote.psk); err != nil {
		t.Fatal(err)
	}
	if site.Address != "10.77.0.2" {
		t.Fatalf("the first site got %s, want 10.77.0.2", site.Address)
	}

	// A reference to a site that does not exist is refused, like any other.
	bad := &store.Host{Type: "proxy", Domains: []string{"bad.test"}, CertMode: "none", Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: "192.168.50.10", Port: 80, Via: 99}}
	if err := st.CreateHost(bad); err == nil {
		t.Fatal("a host naming a site that does not exist was stored")
	}
	// The same address reached two ways inside one host is refused: the
	// connection pools and the balancer keep backends apart by address.
	twice := &store.Host{Type: "proxy", Domains: []string{"twice.test"}, CertMode: "none", Enabled: true,
		Upstream:  store.Upstream{Scheme: "http", Host: "192.168.50.10", Port: 80, Via: site.ID},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "192.168.50.10", Port: 80}}}
	if err := st.CreateHost(twice); err == nil {
		t.Fatal("one address reached both through a site and locally was stored")
	}

	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"via.test"},
		Upstream: store.Upstream{Scheme: "http", Host: "192.168.50.10", Port: 80, Via: site.ID}})
	reload(t, e)
	eventually(t, "the host to answer through the tunnel", func() bool {
		rr := req(e, http.MethodGet, "via.test", "/", "203.0.113.9", nil)
		return rr.Code == http.StatusOK && rr.Body.String() == "from the site"
	})
	select {
	case host := <-remote.hits:
		if host != "via.test" {
			t.Fatalf("the site saw Host %q, want via.test", host)
		}
	default:
		t.Fatal("the answer did not come from the site")
	}

	// The site cannot be deleted while a host reaches something through it.
	if err := st.DeleteWGSite(site.ID); err == nil {
		t.Fatal("a site that a host still uses was deleted")
	}

	// Tunnel off: 502, at once, and not a byte on the host network.
	setSettings(t, st, map[string]string{"wg_enabled": "0"})
	reload(t, e)
	began := time.Now()
	if rr := req(e, http.MethodGet, "via.test", "/", "203.0.113.9", nil); rr.Code != http.StatusBadGateway {
		t.Fatalf("with the tunnel off the host answered %d, want 502", rr.Code)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("the refusal took %v: the upstream was tried somewhere before failing", took)
	}
	if e.WGStatus().Running {
		t.Fatal("the endpoint still runs with wg_enabled off")
	}

	// And back.
	setSettings(t, st, map[string]string{"wg_enabled": "1"})
	reload(t, e)
	eventually(t, "the host to answer again after the tunnel returned", func() bool {
		return req(e, http.MethodGet, "via.test", "/", "203.0.113.9", nil).Code == http.StatusOK
	})
}

// A request whose backend has no site recorded never defaults to the host
// network: the transport refuses it.
func TestTransportRefusesARequestWithoutARecordedSite(t *testing.T) {
	e, _ := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("reached")) })
	v := e.newHostTransports(store.Host{Upstream: up})
	r, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/", up.Host, up.Port), nil)
	if resp, err := v.RoundTrip(r); err == nil {
		resp.Body.Close()
		t.Fatal("a request without a recorded site was sent")
	}
	if resp, err := v.RoundTrip(withVia(r, 0)); err != nil {
		t.Fatalf("the same request with site 0 recorded: %v", err)
	} else {
		resp.Body.Close()
	}
	// A site this host has no pool for is refused too.
	if resp, err := v.RoundTrip(withVia(r, 7)); err == nil {
		resp.Body.Close()
		t.Fatal("a request for a site the host has no pool for was sent")
	}
}

// rawSetting reads a setting's stored bytes, past the store's unsealing.
func rawSetting(t *testing.T, e *Engine, key string) string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(e.cfg.DataDir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
