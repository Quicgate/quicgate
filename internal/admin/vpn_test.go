package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"quicgate/internal/store"
)

// vpnServer is a test server with WireGuard on and an admin logged in.
func vpnServer(t *testing.T) (*Server, string) {
	t.Helper()
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
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_enabled": "1", "wg_port": fmt.Sprint(port), "wg_endpoint": "vpn.example.com:51820"}); rr.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rr.Code, rr.Body.String())
	}
	t.Cleanup(func() { call(t, s, http.MethodPut, "/api/settings", sess, map[string]string{"wg_enabled": "0"}) })
	return s, sess
}

// Devices: the preshared key leaves quicgate once, a key is used once ever,
// and a revoked device's address does not come back to the next one.
func TestWireGuardDevicesAPI(t *testing.T) {
	s, sess := vpnServer(t)
	for _, path := range []string{"/api/wg/devices", "/api/wg/policies", "/api/wg/sessions", "/api/wg/blocked"} {
		if rr := call(t, s, http.MethodGet, path, "", nil); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a session: %d, want 401", path, rr.Code)
		}
	}
	key := randomKey(t)
	rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, map[string]any{"name": "laptop", "publicKey": key})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var dev store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &dev); err != nil || dev.PresharedKey == "" || dev.Address != "10.77.0.2" || dev.Kind != "admin" || !dev.Enabled {
		t.Fatalf("created = %s", rr.Body.String())
	}
	rr = call(t, s, http.MethodGet, "/api/wg/devices", sess, nil)
	if strings.Contains(rr.Body.String(), dev.PresharedKey) {
		t.Fatalf("the list returns the preshared key: %s", rr.Body.String())
	}

	var status struct{ PublicKey string }
	_ = json.Unmarshal(call(t, s, http.MethodGet, "/api/wg/status", sess, nil).Body.Bytes(), &status)
	site := map[string]any{"name": "office", "publicKey": randomKey(t), "networks": []string{"192.168.50.0/24"}, "enabled": true}
	if rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, site); rr.Code != http.StatusCreated {
		t.Fatalf("site: %d %s", rr.Code, rr.Body.String())
	}
	for name, bad := range map[string]map[string]any{
		"the same key again": {"name": "x", "publicKey": key},
		// One key has many spellings: Go's base64 skips line breaks and accepts
		// loose padding bits. Uniqueness is about the 32 bytes.
		"the same key with a line break":  {"name": "x", "publicKey": key[:20] + "\r\n" + key[20:]},
		"the same key with loose padding": {"name": "x", "publicKey": loosePadding(key)},
		"a site's key with a line break":  {"name": "x", "publicKey": site["publicKey"].(string)[:8] + "\n" + site["publicKey"].(string)[8:]},
		"a site's key":                    {"name": "x", "publicKey": site["publicKey"]},
		"the server's own key":            {"name": "x", "publicKey": status.PublicKey},
		"not a key":                       {"name": "x", "publicKey": "AAAA"},
		"no name":                         {"name": " ", "publicKey": randomKey(t)},
		"a chosen kind":                   {"name": "x", "publicKey": randomKey(t), "kind": "breakglass"},
		"chosen routes":                   {"name": "x", "publicKey": randomKey(t), "routes": []map[string]string{{"cidr": "192.168.1.0/24", "proto": "any"}}},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}
	// A device's key cannot become a site's either.
	site2 := map[string]any{"name": "shed", "publicKey": key, "networks": []string{"192.168.60.0/24"}, "enabled": true}
	if rr := call(t, s, http.MethodPost, "/api/wg/sites", sess, site2); rr.Code != http.StatusBadRequest {
		t.Errorf("a site with a device's key: %d %s, want 400", rr.Code, rr.Body.String())
	}

	// Off and on again.
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/enabled", dev.ID), sess, map[string]bool{"enabled": false}); rr.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetWGDevice(dev.ID); got.Enabled {
		t.Fatal("the device is still enabled")
	}

	// Revoked: gone for good, its key and its address with it.
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/devices/%d", dev.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/devices/%d", dev.ID), sess, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d, want 404", rr.Code)
	}
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/enabled", dev.ID), sess, map[string]bool{"enabled": true}); rr.Code != http.StatusNotFound {
		t.Fatalf("enabling a revoked device: %d, want 404", rr.Code)
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, map[string]any{"name": "again", "publicKey": key}); rr.Code != http.StatusBadRequest {
		t.Fatalf("a revoked device's key was accepted again: %d", rr.Code)
	}
	rr = call(t, s, http.MethodPost, "/api/wg/devices", sess, map[string]any{"name": "phone", "publicKey": randomKey(t)})
	var next store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &next); err != nil || rr.Code != http.StatusCreated {
		t.Fatalf("second device: %d %s", rr.Code, rr.Body.String())
	}
	if next.Address == dev.Address || next.Address == "10.77.0.2" {
		t.Fatalf("the next device got the revoked device's address %s straight away", next.Address)
	}
}

// Break-glass devices are the one way to LAN routes without a login, so they
// cost the most to make: password, a second factor, a cap and an expiry.
func TestBreakGlassAPI(t *testing.T) {
	s, sess := vpnServer(t)
	routes := []map[string]string{{"cidr": "192.168.178.0/24", "proto": "tcp", "ports": "22"}}
	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body := func(code string) map[string]any {
		return map[string]any{"name": "safe", "publicKey": randomKey(t), "password": "password-123", "code": code, "routes": routes, "expiresAt": expiry}
	}

	// No second factor on the account: no break-glass device.
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body("000000")); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "two-factor") {
		t.Fatalf("without 2FA on the account: %d %s", rr.Code, rr.Body.String())
	}
	u, err := s.store.GetUserByEmail("admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	otp, err := totp.Generate(totp.GenerateOpts{Issuer: "quicgate", AccountName: u.Email})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetTOTPSecret(u.ID, otp.Secret()); err != nil {
		t.Fatal(err)
	}
	code := func() string {
		c, err := totp.GenerateCode(otp.Secret(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wrong := func() string {
		c := code()
		if c[0] == '9' {
			return "0" + c[1:]
		}
		return "9" + c[1:]
	}

	mutate := func(fn func(map[string]any)) map[string]any { b := body(code()); fn(b); return b }
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"a wrong password":   {mutate(func(b map[string]any) { b["password"] = "nope-nope-nope" }), http.StatusUnauthorized},
		"a wrong code":       {body(wrong()), http.StatusUnauthorized},
		"no code":            {body(""), http.StatusUnauthorized},
		"no routes":          {mutate(func(b map[string]any) { b["routes"] = []any{} }), http.StatusBadRequest},
		"no expiry":          {mutate(func(b map[string]any) { delete(b, "expiresAt") }), http.StatusBadRequest},
		"an expiry gone by":  {mutate(func(b map[string]any) { b["expiresAt"] = "2020-01-01T00:00:00Z" }), http.StatusBadRequest},
		"a public route":     {mutate(func(b map[string]any) { b["routes"] = []map[string]string{{"cidr": "8.8.8.0/24", "proto": "any"}} }), http.StatusBadRequest},
		"everything at once": {mutate(func(b map[string]any) { b["routes"] = []map[string]string{{"cidr": "0.0.0.0/0", "proto": "any"}} }), http.StatusBadRequest},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, tc.body); rr.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rr.Code, rr.Body.String(), tc.want)
		}
	}
	if devices, _ := s.store.ListWGDevices(); len(devices) != 0 {
		t.Fatalf("a refused request left %d devices behind", len(devices))
	}

	rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(code()))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var first store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil || first.Kind != "breakglass" || first.ExpiresAt == "" || len(first.Routes) != 1 || first.PresharedKey == "" {
		t.Fatalf("created = %s", rr.Body.String())
	}
	never := mutate(func(b map[string]any) { delete(b, "expiresAt"); b["neverExpires"] = true })
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, never); rr.Code != http.StatusCreated {
		t.Fatalf("never expires, said explicitly: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(code())); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "two break-glass") {
		t.Fatalf("a third: %d %s, want 400", rr.Code, rr.Body.String())
	}
	// A revoked one makes room.
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/devices/%d", first.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rr.Code)
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(code())); rr.Code != http.StatusCreated {
		t.Fatalf("after a revoke: %d %s", rr.Code, rr.Body.String())
	}
}

// Policies, sessions, blocking and the settings that go with them.
func TestVPNPoliciesSessionsAndSettings(t *testing.T) {
	s, sess := vpnServer(t)
	p := &store.OIDCProvider{Name: "idp", Issuer: "https://idp.example.com", ClientID: "c", ClientSecret: "s"}
	if err := s.store.CreateOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	// Every policy gets a name of its own: a refusal must be about what the
	// case is about, and never about a name that is taken.
	made := 0
	policy := func(subject map[string]any, routes ...map[string]string) map[string]any {
		made++
		return map[string]any{"name": fmt.Sprintf("ops %d", made), "subject": subject, "routes": routes}
	}
	group := map[string]any{"kind": "group", "provider": p.ID, "group": "ops"}
	ssh := map[string]string{"cidr": "192.168.178.0/24", "proto": "tcp", "ports": "22,443"}

	rr := call(t, s, http.MethodPost, "/api/wg/policies", sess, policy(group, ssh))
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var saved store.VPNPolicy
	if err := json.Unmarshal(rr.Body.Bytes(), &saved); err != nil || saved.ID == 0 {
		t.Fatalf("created = %s", rr.Body.String())
	}
	for name, bad := range map[string]map[string]any{
		"a public range":             policy(group, map[string]string{"cidr": "1.1.1.0/24", "proto": "any"}),
		"the whole internet":         policy(group, map[string]string{"cidr": "0.0.0.0/0", "proto": "any"}),
		"IPv6":                       policy(group, map[string]string{"cidr": "fd00::/64", "proto": "any"}),
		"a port out of range":        policy(group, map[string]string{"cidr": "192.168.1.0/24", "proto": "tcp", "ports": "70000"}),
		"a protocol that is not one": policy(group, map[string]string{"cidr": "192.168.1.0/24", "proto": "icmp"}),
		"no routes":                  policy(group),
		"a group with no provider":   policy(map[string]any{"kind": "group", "group": "ops"}, ssh),
		"a provider that is not":     policy(map[string]any{"kind": "group", "provider": 999, "group": "ops"}, ssh),
		"a device as the subject":    policy(map[string]any{"kind": "device", "peer": 1}, ssh),
		"an unknown field":           {"name": "unknown field", "subject": group, "routes": []map[string]string{ssh}, "allowAll": true},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/policies", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}
	if rr := call(t, s, http.MethodPut, "/api/wg/policies/9999", sess, policy(group, ssh)); rr.Code != http.StatusNotFound {
		t.Errorf("update of a policy that is not there: %d, want 404", rr.Code)
	}
	// The provider a policy names cannot be deleted from under it.
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/oidc-providers/%d", p.ID), sess, nil); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "VPN policy ops 1") {
		t.Errorf("deleting a provider a policy names: %d %s, want 400 naming the policy", rr.Code, rr.Body.String())
	}

	// An access list cannot name a provider, a site or a device that is not there.
	for name, vpn := range map[string]map[string]any{
		"a provider that is not": {"kind": "group", "provider": 999, "group": "ops"},
		"a site that is not":     {"kind": "peer", "peer": "site:999"},
		"a device that is not":   {"kind": "peer", "peer": "device:999"},
	} {
		list := map[string]any{"name": "vpn " + name, "satisfy": "any", "rules": []map[string]any{{"action": "allow", "vpn": vpn}}}
		if rr := call(t, s, http.MethodPost, "/api/access-lists", sess, list); rr.Code != http.StatusBadRequest {
			t.Errorf("an access list naming %s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}
	list := map[string]any{"name": "vpn ops", "satisfy": "any", "rules": []map[string]any{{"action": "allow", "vpn": group}}}
	if rr := call(t, s, http.MethodPost, "/api/access-lists", sess, list); rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("an access list naming a group: %d %s", rr.Code, rr.Body.String())
	}

	// Explain: the editor's way to try a policy.
	explain := func(dest string) string {
		rr := call(t, s, http.MethodPost, "/api/wg/explain", sess, map[string]any{"routes": []map[string]string{ssh}, "proto": "tcp", "dest": dest})
		if rr.Code != http.StatusOK {
			t.Fatalf("explain %s: %d %s", dest, rr.Code, rr.Body.String())
		}
		var out struct{ Answer string }
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out.Answer
	}
	if got := explain("192.168.178.20:22"); !strings.HasPrefix(got, "allowed") {
		t.Errorf("explain an allowed flow: %q", got)
	}
	for _, dest := range []string{"192.168.178.20:23", "192.168.179.20:22", "127.0.0.1:22", "169.254.169.254:443"} {
		if got := explain(dest); !strings.HasPrefix(got, "refused") {
			t.Errorf("explain %s: %q, want refused", dest, got)
		}
	}

	// Sessions: listed without the refresh token, ended by an admin.
	now := time.Now()
	v := &store.VPNSession{Provider: p.ID, Sub: "u1", Email: "ann@example.com", Groups: []string{"ops"}, RefreshToken: "rt-secret-value",
		LoginAt: now, RenewedAt: now, LeaseUntil: now.Add(10 * time.Minute), GraceUntil: now.Add(20 * time.Minute), HardUntil: now.Add(24 * time.Hour)}
	if err := s.store.LoginVPNSession(v); err != nil {
		t.Fatal(err)
	}
	rr = call(t, s, http.MethodGet, "/api/wg/sessions", sess, nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ann@example.com") || strings.Contains(rr.Body.String(), "rt-secret-value") {
		t.Fatalf("sessions: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, fmt.Sprintf("/api/wg/sessions/%d/end", v.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("end: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetVPNSession(p.ID, "u1"); got.Live(time.Now()) {
		t.Fatal("the session is still live after an admin ended it")
	}

	// Blocking outlives a login; unblocking lifts it.
	if rr := call(t, s, http.MethodPost, "/api/wg/owners/block", sess, map[string]any{"provider": p.ID, "sub": ""}); rr.Code != http.StatusBadRequest {
		t.Errorf("block without a subject: %d, want 400", rr.Code)
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/owners/block", sess, map[string]any{"provider": p.ID, "sub": "u1", "email": "ann@example.com"}); rr.Code != http.StatusNoContent {
		t.Fatalf("block: %d %s", rr.Code, rr.Body.String())
	}
	if err := s.store.LoginVPNSession(v); err == nil {
		t.Fatal("a blocked owner could log in")
	}
	if rr := call(t, s, http.MethodGet, "/api/wg/blocked", sess, nil); !strings.Contains(rr.Body.String(), "ann@example.com") {
		t.Fatalf("blocked list: %s", rr.Body.String())
	}
	if rr := call(t, s, http.MethodPost, "/api/wg/owners/unblock", sess, map[string]any{"provider": p.ID, "sub": "u1"}); rr.Code != http.StatusNoContent {
		t.Fatalf("unblock: %d", rr.Code)
	}
	if err := s.store.LoginVPNSession(v); err != nil {
		t.Fatalf("login after the block was lifted: %v", err)
	}

	// Settings.
	for _, bad := range []map[string]string{
		{"wg_lease_minutes": "1"}, {"wg_lease_minutes": "soon"}, {"wg_outage_grace_minutes": "61"}, {"wg_session_days": "0"},
		{"wg_auth_max_age": "10"}, {"wg_devices_per_user": "0"}, {"wg_protected_endpoints": "not-an-address"},
	} {
		if rr := call(t, s, http.MethodPut, "/api/settings", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("settings %v: %d, want 400", bad, rr.Code)
		}
	}
	good := map[string]string{"wg_lease_minutes": "10", "wg_outage_grace_minutes": "0", "wg_session_days": "30", "wg_auth_max_age": "900",
		"wg_devices_per_user": "3", "wg_protected_endpoints": "192.168.178.54, 192.168.178.1:8443"}
	if rr := call(t, s, http.MethodPut, "/api/settings", sess, good); rr.Code != http.StatusOK {
		t.Fatalf("good settings: %d %s", rr.Code, rr.Body.String())
	}

	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/policies/%d", saved.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
}

// loosePadding returns another base64 spelling of the same 32 bytes: the last
// character before the padding carries two unused bits.
func loosePadding(key string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, key[42])
	return key[:42] + string(alphabet[i|1]) + key[43:]
}
