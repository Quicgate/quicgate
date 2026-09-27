package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// The tunnel network is fixed while a device lives in it, as it is for sites
// (L-34): every device's address and configuration name it. A revoked device
// keeps no configuration and does not hold the network.
func TestTheTunnelNetworkIsFixedWhileDevicesExist(t *testing.T) {
	s, sess := vpnServer(t)
	rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, map[string]any{"name": "laptop", "publicKey": randomKey(t)})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var dev store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &dev); err != nil {
		t.Fatal(err)
	}
	rr = call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_network": "10.88.0.0/24"})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "devices") {
		t.Fatalf("moving the tunnel network with a device in it: %d %s, want 400 naming devices", rr.Code, rr.Body.String())
	}
	if got := s.store.GetSetting("wg_network", ""); got == "10.88.0.0/24" {
		t.Fatal("the network was changed anyway")
	}
	// A disabled device still holds its address.
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/enabled", dev.ID), sess, map[string]bool{"enabled": false}); rr.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_network": "10.88.0.0/24"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("moving the tunnel network with a disabled device in it: %d, want 400", rr.Code)
	}
	// Revoked: the network is free to move.
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/devices/%d", dev.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_network": "10.88.0.0/24"}); rr.Code != http.StatusOK {
		t.Fatalf("moving the tunnel network with only a revoked device: %d %s, want 200", rr.Code, rr.Body.String())
	}
}

// A site's endpoint is validated beyond host:port (L-38): loopback, the
// unspecified, multicast and link-local addresses are refused, and so is one
// of quicgate's own listeners on one of its own addresses.
func TestSiteEndpointsMustBeReachablePeers(t *testing.T) {
	s, sess := vpnServer(t)
	site := func(endpoint string) map[string]any {
		return map[string]any{"name": "office", "publicKey": randomKey(t), "networks": []string{"192.168.50.0/24"}, "endpoint": endpoint, "enabled": true}
	}
	var status struct{ Port int }
	if err := json.Unmarshal(call(t, s, http.MethodGet, "/api/wg/status", sess, nil).Body.Bytes(), &status); err != nil || status.Port == 0 {
		t.Fatalf("status: %v", err)
	}
	bad := map[string]string{
		"loopback":    "127.0.0.1:51820",
		"unspecified": "0.0.0.0:51820",
		"multicast":   "224.0.0.1:51820",
		"link-local":  "169.254.169.254:51820",
		"no port":     "office.example.com",
	}
	// This machine's own address with quicgate's own WireGuard port: quicgate
	// would shake hands with itself.
	for _, a := range s.engine.OwnAddresses() {
		if ip, err := netip.ParseAddr(a.IP); err == nil && ip.Is4() && !ip.IsLoopback() {
			bad["quicgate's own listener"] = fmt.Sprintf("%s:%d", ip, status.Port)
			break
		}
	}
	for name, endpoint := range bad {
		if rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, site(endpoint)); rr.Code != http.StatusBadRequest {
			t.Errorf("%s (%s): %d %s, want 400", name, endpoint, rr.Code, rr.Body.String())
		}
	}
	rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, site("office.example.com:51820"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("a site with a proper endpoint: %d %s", rr.Code, rr.Body.String())
	}
	var created store.WGSite
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	upd := map[string]any{"name": "office", "publicKey": created.PublicKey, "networks": []string{"192.168.50.0/24"}, "endpoint": "127.0.0.1:51820", "enabled": true}
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/sites/%d", created.ID), sess, upd); rr.Code != http.StatusBadRequest {
		t.Fatalf("an update to a loopback endpoint: %d %s, want 400", rr.Code, rr.Body.String())
	}
}
