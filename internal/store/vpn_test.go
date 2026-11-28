package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
)

// Only a device the admin added carries local addresses of its own. A
// person's device and a revoked device are never given any, whoever asks.
func TestSetWGDeviceAccess(t *testing.T) {
	s := openTestStore(t)
	tunnel := netip.MustParsePrefix("10.77.0.0/24")
	mk := func(name, kind string) WGDevice {
		raw := make([]byte, 32)
		copy(raw, name)
		d := WGDevice{Name: name, Kind: kind, PublicKey: base64.StdEncoding.EncodeToString(raw), Enabled: true}
		if err := s.CreateWGDevice(&d, tunnel, "psk-"+name, 0); err != nil {
			t.Fatal(err)
		}
		return d
	}
	admin, old, person, gone := mk("admin", "admin"), mk("old", "breakglass"), mk("person", "sso"), mk("gone", "admin")
	if err := s.RevokeWGDevice(gone.ID, nil); err != nil {
		t.Fatal(err)
	}
	routes := []VPNRoute{{Name: " NAS ", CIDR: "192.168.1.10", Ports: "445"}}
	for _, d := range []WGDevice{admin, old} {
		if err := s.SetWGDeviceAccess(d.ID, routes, "2030-01-01T00:00:00Z"); err != nil {
			t.Fatalf("%s: %v", d.Name, err)
		}
		got, _ := s.GetWGDevice(d.ID)
		if len(got.Routes) != 1 || got.Routes[0].Name != "NAS" || got.Routes[0].CIDR != "192.168.1.10/32" || got.Routes[0].Proto != "any" || got.ExpiresAt != "2030-01-01T00:00:00Z" {
			t.Fatalf("%s stored as %+v", d.Name, got)
		}
	}
	for _, d := range []WGDevice{person, gone} {
		if err := s.SetWGDeviceAccess(d.ID, routes, ""); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("%s: err = %v, want sql.ErrNoRows", d.Name, err)
		}
		if got, _ := s.GetWGDevice(d.ID); len(got.Routes) != 0 {
			t.Fatalf("%s got routes: %+v", d.Name, got.Routes)
		}
	}
	if err := s.SetWGDeviceAccess(admin.ID, []VPNRoute{{CIDR: "8.8.8.8/32"}}, ""); err == nil {
		t.Fatal("a public address was stored as a route")
	}
	if err := s.SetWGDeviceAccess(admin.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetWGDevice(admin.ID); len(got.Routes) != 0 || got.ExpiresAt != "" {
		t.Fatalf("after clearing: %+v", got)
	}
}
