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

	"quicgate/internal/engine"
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
		"an end date without addresses":   {"name": "x", "publicKey": randomKey(t), "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		"no end date without addresses":   {"name": "x", "publicKey": randomKey(t), "neverExpires": true},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
	}
	// Addresses on the local network are never had for the asking: without the
	// password and the second factor the request is refused and leaves nothing.
	withRoutes := map[string]any{"name": "x", "publicKey": randomKey(t), "routes": []map[string]string{{"cidr": "192.168.1.0/24", "proto": "any"}},
		"expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, withRoutes); rr.Code != http.StatusUnauthorized {
		t.Errorf("routes without a password: %d %s, want 401", rr.Code, rr.Body.String())
	}
	if devices, _ := s.store.ListWGDevices(); len(devices) != 1 {
		t.Fatalf("a refused request left a device behind: %d devices, want 1", len(devices))
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

// The older call for a device with local addresses and no login behind it. It
// is the same thing as POST /api/wg/devices with routes now: it costs the
// password, a second factor and an end date, and there is no cap of two.
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
	// A code is good once: the clock the server checks codes against is under
	// the test's control, and moves on one step for every device it makes.
	base := time.Now()
	step := 0
	totpNow = func() time.Time { return base.Add(time.Duration(step) * totpPeriod * time.Second) }
	t.Cleanup(func() { totpNow = time.Now })
	code := func() string {
		c, err := totp.GenerateCode(otp.Secret(), totpNow())
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

	used := code()
	rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(used))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var first store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil || first.Kind != "admin" || first.ExpiresAt == "" || len(first.Routes) != 1 || first.PresharedKey == "" {
		t.Fatalf("created = %s", rr.Body.String())
	}
	// The code that made the first device is spent.
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(used)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("the same code again: %d %s, want 401", rr.Code, rr.Body.String())
	}
	step++
	never := mutate(func(b map[string]any) { delete(b, "expiresAt"); b["neverExpires"] = true })
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, never); rr.Code != http.StatusCreated {
		t.Fatalf("never expires, said explicitly: %d %s", rr.Code, rr.Body.String())
	}
	step++
	// There is no cap of two any more.
	if rr := call(t, s, http.MethodPost, "/api/wg/breakglass", sess, body(code())); rr.Code != http.StatusCreated {
		t.Fatalf("a third: %d %s, want 201", rr.Code, rr.Body.String())
	}
}

// withTOTP switches two-factor on for the test admin and puts the clock the
// server checks codes against under the test's control: a code is good once,
// so the test moves on one step (next) before it needs a fresh one.
func withTOTP(t *testing.T, s *Server) (code, wrong func() string, next func()) {
	t.Helper()
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
	base := time.Now()
	step := 0
	totpNow = func() time.Time { return base.Add(time.Duration(step) * totpPeriod * time.Second) }
	t.Cleanup(func() { totpNow = time.Now })
	code = func() string {
		c, err := totp.GenerateCode(otp.Secret(), totpNow())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wrong = func() string {
		c := code()
		if c[0] == '9' {
			return "0" + c[1:]
		}
		return "9" + c[1:]
	}
	return code, wrong, func() { step++ }
}

// A device the admin adds can carry addresses on the local network of its
// own. Nobody logs in behind such a device, so every way to give it addresses
// costs the password and a second factor, an end date unless waived in so
// many words, and only private address space can be named.
func TestDeviceLocalAccessOnCreate(t *testing.T) {
	s, sess := vpnServer(t)
	routes := []map[string]string{{"name": "NAS", "cidr": "192.168.1.10/32", "proto": "tcp", "ports": "445"}}
	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body := func(code string) map[string]any {
		return map[string]any{"name": "phone", "publicKey": randomKey(t), "password": "password-123", "code": code, "routes": routes, "expiresAt": expiry}
	}
	// No second factor on the account: no local addresses.
	if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, body("000000")); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "two-factor") {
		t.Fatalf("without 2FA on the account: %d %s", rr.Code, rr.Body.String())
	}
	code, wrong, next := withTOTP(t, s)
	mutate := func(fn func(map[string]any)) map[string]any { b := body(code()); fn(b); return b }
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"a wrong password": {mutate(func(b map[string]any) { b["password"] = "nope-nope-nope" }), http.StatusUnauthorized},
		"no password":      {mutate(func(b map[string]any) { delete(b, "password") }), http.StatusUnauthorized},
		"a wrong code":     {body(wrong()), http.StatusUnauthorized},
		"no code":          {body(""), http.StatusUnauthorized},
		"no end date":      {mutate(func(b map[string]any) { delete(b, "expiresAt") }), http.StatusBadRequest},
		"an end date gone": {mutate(func(b map[string]any) { b["expiresAt"] = "2020-01-01T00:00:00Z" }), http.StatusBadRequest},
		"a public address": {mutate(func(b map[string]any) { b["routes"] = []map[string]string{{"cidr": "8.8.8.8/32", "proto": "any"}} }), http.StatusBadRequest},
		"everything":       {mutate(func(b map[string]any) { b["routes"] = []map[string]string{{"cidr": "0.0.0.0/0", "proto": "any"}} }), http.StatusBadRequest},
		"a name with a tab": {mutate(func(b map[string]any) {
			b["routes"] = []map[string]string{{"name": "N\tAS", "cidr": "192.168.1.10/32"}}
		}), http.StatusBadRequest},
		"a name too long": {mutate(func(b map[string]any) {
			b["routes"] = []map[string]string{{"name": strings.Repeat("n", 65), "cidr": "192.168.1.10/32"}}
		}), http.StatusBadRequest},
		"a chosen kind": {mutate(func(b map[string]any) { b["kind"] = "sso" }), http.StatusBadRequest},
	} {
		if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, tc.body); rr.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rr.Code, rr.Body.String(), tc.want)
		}
	}
	if devices, _ := s.store.ListWGDevices(); len(devices) != 0 {
		t.Fatalf("a refused request left %d devices behind", len(devices))
	}

	used := code()
	rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, body(used))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var dev store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &dev); err != nil || dev.Kind != "admin" || dev.ExpiresAt == "" || dev.PresharedKey == "" ||
		len(dev.Routes) != 1 || dev.Routes[0].Name != "NAS" || dev.Routes[0].CIDR != "192.168.1.10/32" || dev.Routes[0].Ports != "445" {
		t.Fatalf("created = %s", rr.Body.String())
	}
	// The list shows what the device may reach, name included.
	var listed []store.WGDevice
	_ = json.Unmarshal(call(t, s, http.MethodGet, "/api/wg/devices", sess, nil).Body.Bytes(), &listed)
	if len(listed) != 1 || len(listed[0].Routes) != 1 || listed[0].Routes[0].Name != "NAS" || listed[0].ExpiresAt != dev.ExpiresAt {
		t.Fatalf("listed = %+v", listed)
	}
	// The code that made the device is spent.
	if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, body(used)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("the same code again: %d %s, want 401", rr.Code, rr.Body.String())
	}
	// No end date, said in so many words, and no cap on how many there are.
	for i := 0; i < 3; i++ {
		next()
		never := mutate(func(b map[string]any) { delete(b, "expiresAt"); b["neverExpires"] = true })
		if rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, never); rr.Code != http.StatusCreated {
			t.Fatalf("device %d without an end date: %d %s", i+2, rr.Code, rr.Body.String())
		}
	}
	// The overview counts them: they reach the local network without a login.
	ov := s.vpnOverview()
	if ov["localAccessDevices"] != 4 || ov["localAccessNoExpiry"] != 3 {
		t.Fatalf("overview = %v, want 4 devices with local access, 3 of them without an end date", ov)
	}
}

// Changing what a device may reach later costs the same as giving it at the
// start, also when the change takes addresses away: the call is one, and a
// stolen session must not be able to widen a device by "editing" it.
func TestDeviceLocalAccessChange(t *testing.T) {
	s, sess := vpnServer(t)
	rr := call(t, s, http.MethodPost, "/api/wg/devices", sess, map[string]any{"name": "laptop", "publicKey": randomKey(t)})
	var dev store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &dev); err != nil || rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	path := fmt.Sprintf("/api/wg/devices/%d/access", dev.ID)
	routes := []map[string]string{{"name": "NAS", "cidr": "192.168.1.10", "proto": "tcp", "ports": "445"}}
	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	body := func(code string) map[string]any {
		return map[string]any{"password": "password-123", "code": code, "routes": routes, "expiresAt": expiry}
	}
	if rr := call(t, s, http.MethodPut, path, "", body("000000")); rr.Code != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", rr.Code)
	}
	if rr := call(t, s, http.MethodPut, path, sess, body("000000")); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "two-factor") {
		t.Fatalf("without 2FA on the account: %d %s", rr.Code, rr.Body.String())
	}
	code, wrong, next := withTOTP(t, s)
	mutate := func(fn func(map[string]any)) map[string]any { b := body(code()); fn(b); return b }
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"a wrong password":       {mutate(func(b map[string]any) { b["password"] = "nope-nope-nope" }), http.StatusUnauthorized},
		"no password":            {mutate(func(b map[string]any) { delete(b, "password") }), http.StatusUnauthorized},
		"a wrong code":           {body(wrong()), http.StatusUnauthorized},
		"no code":                {body(""), http.StatusUnauthorized},
		"no end date":            {mutate(func(b map[string]any) { delete(b, "expiresAt") }), http.StatusBadRequest},
		"a public address":       {mutate(func(b map[string]any) { b["routes"] = []map[string]string{{"cidr": "1.1.1.1/32"}} }), http.StatusBadRequest},
		"taking away, no code":   {map[string]any{"password": "password-123", "routes": []any{}}, http.StatusUnauthorized},
		"an end date, no routes": {mutate(func(b map[string]any) { b["routes"] = []any{} }), http.StatusBadRequest},
	} {
		if rr := call(t, s, http.MethodPut, path, sess, tc.body); rr.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rr.Code, rr.Body.String(), tc.want)
		}
	}
	if got, _ := s.store.GetWGDevice(dev.ID); len(got.Routes) != 0 || got.ExpiresAt != "" {
		t.Fatalf("a refused change left its mark: %+v", got)
	}
	if rr := call(t, s, http.MethodPut, "/api/wg/devices/999/access", sess, body(code())); rr.Code != http.StatusNotFound {
		t.Fatalf("a device that does not exist: %d %s, want 404", rr.Code, rr.Body.String())
	}

	next()
	used := code()
	rr = call(t, s, http.MethodPut, path, sess, body(used))
	var changed store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &changed); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}
	if len(changed.Routes) != 1 || changed.Routes[0].CIDR != "192.168.1.10/32" || changed.Routes[0].Name != "NAS" || changed.ExpiresAt == "" || changed.PresharedKey != "" || changed.Kind != "admin" {
		t.Fatalf("changed = %s", rr.Body.String())
	}
	if got, _ := s.store.GetWGDevice(dev.ID); len(got.Routes) != 1 || got.ExpiresAt != changed.ExpiresAt {
		t.Fatalf("stored = %+v", got)
	}
	if rr := call(t, s, http.MethodPut, path, sess, body(used)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("the same code again: %d, want 401", rr.Code)
	}
	// Back to private hosts only: the addresses and the end date go.
	next()
	if rr := call(t, s, http.MethodPut, path, sess, map[string]any{"password": "password-123", "code": code(), "routes": []any{}}); rr.Code != http.StatusOK {
		t.Fatalf("taking the addresses away: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetWGDevice(dev.ID); len(got.Routes) != 0 || got.ExpiresAt != "" {
		t.Fatalf("after taking the addresses away: %+v", got)
	}

	// What a person's device may reach follows from the rules for the person:
	// it has no addresses of its own, whatever the admin's second factor says.
	_, tunnel, _, err := engine.WGSettings(s.store)
	if err != nil {
		t.Fatal(err)
	}
	person := store.WGDevice{Name: "anna", Kind: "sso", PublicKey: randomKey(t), Provider: 1, Sub: "anna", Enabled: true}
	if err := s.store.CreateWGDevice(&person, tunnel, randomKey(t), 0); err != nil {
		t.Fatal(err)
	}
	next()
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/access", person.ID), sess, body(code())); rr.Code != http.StatusBadRequest {
		t.Fatalf("a person's device: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetWGDevice(person.ID); len(got.Routes) != 0 {
		t.Fatalf("a person's device got routes of its own: %+v", got)
	}
	// A removed device stays removed.
	if rr := call(t, s, http.MethodDelete, fmt.Sprintf("/api/wg/devices/%d", dev.ID), sess, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rr.Code)
	}
	next()
	if rr := call(t, s, http.MethodPut, path, sess, body(code())); rr.Code != http.StatusNotFound {
		t.Fatalf("a revoked device: %d %s, want 404", rr.Code, rr.Body.String())
	}
	if got, _ := s.store.GetWGDevice(dev.ID); len(got.Routes) != 0 {
		t.Fatalf("a revoked device got routes: %+v", got)
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

	// The issuer behind a provider the VPN knows people from cannot change: the
	// same subject id under another issuer is another person (QG-09).
	edit := map[string]any{"name": "idp renamed", "issuer": "https://other.example.com", "clientId": "c"}
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/oidc-providers/%d", p.ID), sess, edit); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "issuer cannot change") {
		t.Errorf("changing the issuer under a VPN policy: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if all, _ := s.store.ListOIDCProviders(); len(all) != 1 || all[0].Issuer != "https://idp.example.com" {
		t.Errorf("the issuer changed: %+v", all)
	}
	edit["issuer"] = "https://idp.example.com"
	if rr := call(t, s, http.MethodPut, fmt.Sprintf("/api/oidc-providers/%d", p.ID), sess, edit); rr.Code != http.StatusOK {
		t.Errorf("renaming the provider: %d %s", rr.Code, rr.Body.String())
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

// An API token has no password and no second factor, so it can add a plain
// device and nothing more: not one with local addresses, and no change of
// what a device may reach.
func TestAnAPITokenCannotGiveADeviceLocalAccess(t *testing.T) {
	s, _ := vpnServer(t)
	withTOTP(t, s)
	tok := mustToken(t, s, store.TokenFull)
	rr := bearer(t, s, http.MethodPost, "/api/wg/devices", tok, map[string]any{"name": "plain", "publicKey": randomKey(t)})
	var dev store.WGDevice
	if err := json.Unmarshal(rr.Body.Bytes(), &dev); err != nil || rr.Code != http.StatusCreated {
		t.Fatalf("a plain device with a full token: %d %s", rr.Code, rr.Body.String())
	}
	routes := []map[string]string{{"cidr": "192.168.1.10/32"}}
	withRoutes := map[string]any{"name": "x", "publicKey": randomKey(t), "routes": routes, "neverExpires": true, "password": "password-123", "code": "000000"}
	if rr := bearer(t, s, http.MethodPost, "/api/wg/devices", tok, withRoutes); rr.Code < 400 {
		t.Fatalf("a device with local addresses with a token: %d %s", rr.Code, rr.Body.String())
	}
	change := map[string]any{"routes": routes, "neverExpires": true, "password": "password-123", "code": "000000"}
	if rr := bearer(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/access", dev.ID), tok, change); rr.Code < 400 {
		t.Fatalf("changing access with a token: %d %s", rr.Code, rr.Body.String())
	}
	for _, access := range []string{store.TokenMonitor, store.TokenSwitch} {
		if rr := bearer(t, s, http.MethodPut, fmt.Sprintf("/api/wg/devices/%d/access", dev.ID), mustToken(t, s, access), change); rr.Code != http.StatusForbidden {
			t.Fatalf("changing access with a %s token: %d, want 403", access, rr.Code)
		}
	}
	devices, _ := s.store.ListWGDevices()
	if len(devices) != 1 || len(devices[0].Routes) != 0 {
		t.Fatalf("devices = %+v, want the one plain device without routes", devices)
	}
}
