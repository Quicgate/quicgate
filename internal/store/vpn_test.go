package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
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

// A database from before 1.21.0 has no columns for who added a device and
// when it was seen. Opening it adds them and leaves every row as it was: the
// new fields are empty, never a guess.
func TestOldDeviceRowsGainTheNewColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE wg_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'admin',
  public_key TEXT UNIQUE NOT NULL, psk TEXT NOT NULL DEFAULT '', address TEXT UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1, revoked_at TEXT NOT NULL DEFAULT '', provider INTEGER NOT NULL DEFAULT 0,
  sub TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', routes TEXT NOT NULL DEFAULT '[]',
  expires_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
INSERT INTO wg_devices (name, kind, public_key, address, provider, sub, email, routes, created_at)
VALUES ('My Phone 2', 'sso', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', '10.77.0.2', 1, 'anna', 'anna@example.com', '[]', '2026-09-19T10:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	since := ""
	for round := 0; round < 2; round++ { // opening twice must be as good as once
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open, round %d: %v", round, err)
		}
		devices, err := s.ListWGDevices()
		if err != nil || len(devices) != 1 {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		d := devices[0]
		if d.Name != "My Phone 2" || d.Kind != "sso" || d.Email != "anna@example.com" || d.CreatedAt != "2026-09-19T10:00:00Z" || !d.Enabled {
			t.Fatalf("the old row changed: %+v", d)
		}
		if d.AddedBy != "" || d.FirstSeenAt != "" || d.LastSeenAt != "" {
			t.Fatalf("the new fields of an old row are not empty: %+v", d)
		}
		// From when "last seen" is kept is written down once, at the first
		// start that keeps it: a device older than that with no time on
		// record was not "never connected", it is simply not known.
		got := s.GetSetting("wg_seen_since", "")
		if _, err := time.Parse(time.RFC3339, got); err != nil {
			_ = s.Close()
			t.Fatalf("wg_seen_since = %q, want a time", got)
		}
		if round == 0 {
			since = got
			if _, err := s.db.Exec("UPDATE settings SET value='2026-01-01T00:00:00Z' WHERE key='wg_seen_since'"); err != nil {
				t.Fatal(err)
			}
		} else if got != "2026-01-01T00:00:00Z" {
			t.Fatalf("wg_seen_since was written again at a later start: %q (first %q)", got, since)
		}
		_ = s.Close()
	}
}

// When a device was seen only ever moves forward, and the first time stays.
func TestMarkWGDeviceSeen(t *testing.T) {
	s := openTestStore(t)
	d := WGDevice{Name: "phone", Kind: "admin", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Enabled: true, AddedBy: "admin@example.com"}
	if err := s.CreateWGDevice(&d, netip.MustParsePrefix("10.77.0.0/24"), "psk", 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetWGDevice(d.ID); got.AddedBy != "admin@example.com" || got.LastSeenAt != "" || got.FirstSeenAt != "" {
		t.Fatalf("a new device: %+v", got)
	}
	at := func(v string) time.Time { ts, _ := time.Parse(time.RFC3339, v); return ts }
	for _, step := range []struct{ seen, wantFirst, wantLast string }{
		{"2026-11-28T10:00:00Z", "2026-11-28T10:00:00Z", "2026-11-28T10:00:00Z"},
		{"2026-11-28T12:00:00Z", "2026-11-28T10:00:00Z", "2026-11-28T12:00:00Z"},
		{"2026-11-28T11:00:00Z", "2026-11-28T10:00:00Z", "2026-11-28T12:00:00Z"}, // an older time changes nothing
	} {
		if err := s.MarkWGDeviceSeen(d.ID, at(step.seen)); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetWGDevice(d.ID)
		if got.FirstSeenAt != step.wantFirst || got.LastSeenAt != step.wantLast {
			t.Fatalf("after %s: first %q last %q, want %q and %q", step.seen, got.FirstSeenAt, got.LastSeenAt, step.wantFirst, step.wantLast)
		}
	}
	if err := s.MarkWGDeviceSeen(d.ID, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetWGDevice(d.ID); got.LastSeenAt != "2026-11-28T12:00:00Z" {
		t.Fatalf("a zero time was stored: %+v", got)
	}
}
