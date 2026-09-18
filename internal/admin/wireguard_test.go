package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"quicgate/internal/store"
)

func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// The sites API: the preshared key leaves quicgate once, the server's private
// key never, and what would break silently is refused.
func TestWireGuardSitesAPI(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	s := newTestServer(t)
	mustUser(t, s, "admin@example.com", "password-123")
	sess := login(t, s, "admin@example.com", "password-123")
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	site := map[string]any{"name": "office", "publicKey": randomKey(t), "networks": []string{"192.168.50.0/24"}, "endpoint": "office.example.com:51820", "keepalive": 25, "enabled": true}

	// Off: no site can be made, because its configuration needs the server key.
	if rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, site); rr.Code != http.StatusBadRequest {
		t.Fatalf("create with WireGuard off: %d %s, want 400", rr.Code, rr.Body.String())
	}
	for _, bad := range []map[string]string{{"wg_port": "99999"}, {"wg_network": "10.77.0.0/8"}, {"wg_network": "fd00::/64"}, {"wg_endpoint": "no-port"}} {
		if rr := call(t, s, http.MethodPut, "/api/settings", sess, bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("settings %v: %d, want 400", bad, rr.Code)
		}
	}
	rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(port), "wg_endpoint": "vpn.example.com:51820"})
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rr.Code, rr.Body.String())
	}
	t.Cleanup(func() { call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_enabled": "0"}) })
	if strings.Contains(rr.Body.String(), "wg_private_key") {
		t.Fatal("the settings API mentions the server's private key")
	}
	private := s.store.GetSetting("wg_private_key", "")
	if private == "" {
		t.Fatal("enabling WireGuard did not create a server key")
	}

	var status struct {
		Running   bool
		PublicKey string
		Address   string
	}
	rr = call(t, s, http.MethodGet, "/api/wg/status", sess, nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil || !status.Running || status.PublicKey == "" || status.Address != "10.77.0.1" {
		t.Fatalf("status = %s (%v)", rr.Body.String(), err)
	}
	if strings.Contains(rr.Body.String(), private) {
		t.Fatal("the status holds the server's private key")
	}
	if rr := call(t, s, http.MethodGet, "/api/wg/status", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without a session: %d, want 401", rr.Code)
	}

	// Create: the preshared key comes back, once.
	rr = call(t, s, http.MethodPost, "/api/wg/sites", sess, site)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created store.WGSite
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil || created.PresharedKey == "" || created.Address != "10.77.0.2" {
		t.Fatalf("created = %s", rr.Body.String())
	}
	rr = call(t, s, http.MethodGet, "/api/wg/sites", sess, nil)
	if strings.Contains(rr.Body.String(), created.PresharedKey) || strings.Contains(rr.Body.String(), "presharedKey") {
		t.Fatalf("the list returns the preshared key: %s", rr.Body.String())
	}
	upd := map[string]any{"name": "office", "publicKey": site["publicKey"], "networks": []string{"192.168.50.0/24", "192.168.51.0/24"}, "endpoint": "", "keepalive": 25, "enabled": true}
	rr = call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/sites/%d", created.ID), sess, upd)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), created.PresharedKey) {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetWGSite(created.ID); got.PresharedKey != created.PresharedKey || got.Address != "10.77.0.2" {
		t.Fatal("an update changed the preshared key or the address")
	}

	// Refused: what validation is for.
	for name, bad := range map[string]map[string]any{
		"the server's own key":   {"name": "x", "publicKey": status.PublicKey, "networks": []string{"192.168.60.0/24"}},
		"another site's key":     {"name": "x", "publicKey": site["publicKey"], "networks": []string{"192.168.60.0/24"}},
		"another site's network": {"name": "x", "publicKey": randomKey(t), "networks": []string{"192.168.50.128/25"}},
		"the tunnel network":     {"name": "x", "publicKey": randomKey(t), "networks": []string{"10.77.0.0/16"}},
		"loopback":               {"name": "x", "publicKey": randomKey(t), "networks": []string{"127.0.0.0/8"}},
		"no network":             {"name": "x", "publicKey": randomKey(t), "networks": []string{}},
		"a chosen address":       {"name": "x", "publicKey": randomKey(t), "networks": []string{"192.168.60.0/24"}, "bogus": true},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}

	// The tunnel network is fixed once a site lives in it.
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_network": "10.88.0.0/24"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("moving the tunnel network with a site in it: %d, want 400", rr.Code)
	}

	// A site that a host still reaches something through cannot be deleted.
	h := &store.Host{Type: "proxy", Domains: []string{"via.test"}, CertMode: "none", Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: "192.168.50.10", Port: 80, Via: created.ID}}
	if err := s.store.CreateHost(h); err != nil {
		t.Fatal(err)
	}
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/sites/%d", created.ID), sess, nil); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "via.test") {
		t.Fatalf("delete of a site in use: %d %s, want 409 naming the host", rr.Code, rr.Body.String())
	}
	if err := s.store.DeleteHost(h.ID); err != nil {
		t.Fatal(err)
	}
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/sites/%d", created.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
}
