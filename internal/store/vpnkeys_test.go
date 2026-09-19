package store

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

func testKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// spellings returns other base64 texts that Go's lenient decoder reads as the
// same 32 bytes.
func spellings(key string) map[string]string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, key[42])
	return map[string]string{
		"a line break inside":  key[:20] + "\r\n" + key[20:],
		"a newline at the end": key + "\n",
		"loose padding bits":   key[:42] + string(alphabet[i|1]) + key[43:],
	}
}

// The uniqueness of a WireGuard key is about its 32 bytes (QG-01). Inside
// WireGuard one key is one peer: a second row with the same bytes would take
// over the first one's addresses and preshared key.
func TestWireGuardKeysAreUniqueByTheirBytes(t *testing.T) {
	t.Setenv("QG_SECRET_KEY", "")
	t.Setenv("QG_SECRET_KEY_FILE", "")
	s := openTestStore(t)
	tunnel := netip.MustParsePrefix("10.77.0.0/24")
	psk := testKey(t)

	deviceKey, siteKey, revokedKey := testKey(t), testKey(t), testKey(t)
	victim := &WGDevice{Name: "victim", Kind: "admin", PublicKey: deviceKey, Enabled: true}
	if err := s.CreateWGDevice(victim, tunnel, psk, 0); err != nil {
		t.Fatal(err)
	}
	site := &WGSite{Name: "office", PublicKey: siteKey, Networks: []string{"192.168.50.0/24"}, Enabled: true}
	if err := s.CreateWGSite(site, tunnel, psk); err != nil {
		t.Fatal(err)
	}
	gone := &WGDevice{Name: "gone", Kind: "admin", PublicKey: revokedKey, Enabled: true}
	if err := s.CreateWGDevice(gone, tunnel, psk, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeWGDevice(gone.ID, nil); err != nil {
		t.Fatal(err)
	}

	for owner, key := range map[string]string{"a device's key": deviceKey, "a site's key": siteKey, "a revoked device's key": revokedKey} {
		for how, text := range spellings(key) {
			d := &WGDevice{Name: "x", Kind: "admin", PublicKey: text, Enabled: true}
			if err := s.CreateWGDevice(d, tunnel, psk, 0); err == nil {
				t.Errorf("a device with %s, written with %s, was accepted", owner, how)
			}
			w := &WGSite{Name: "x " + how, PublicKey: text, Networks: []string{"192.168.60.0/24"}, Enabled: true}
			if err := s.CreateWGSite(w, tunnel, psk); err == nil {
				t.Errorf("a site with %s, written with %s, was accepted", owner, how)
			}
		}
	}
	// The victim is what it was.
	got, err := s.GetWGDevice(victim.ID)
	if err != nil || got.PublicKey != deviceKey || got.PresharedKey != psk || got.Address != victim.Address {
		t.Fatalf("the first device changed: %+v (%v)", got, err)
	}

	// A site keeps its key: another key is another site, and another spelling
	// of its own key changes nothing.
	site.PublicKey = testKey(t)
	if err := s.UpdateWGSite(site); err == nil {
		t.Error("an update gave a site another key")
	}
	site.PublicKey = deviceKey
	if err := s.UpdateWGSite(site); err == nil {
		t.Error("an update gave a site a device's key")
	}
	site.PublicKey, site.Name = siteKey, "head office"
	if err := s.UpdateWGSite(site); err != nil {
		t.Fatalf("an update that keeps the key: %v", err)
	}
	if got, _ := s.GetWGSite(site.ID); got.PublicKey != siteKey || got.Name != "head office" {
		t.Fatalf("after the update: %+v", got)
	}

	// A legitimate second device still gets in.
	if err := s.CreateWGDevice(&WGDevice{Name: "other", Kind: "admin", PublicKey: testKey(t), Enabled: true}, tunnel, psk, 0); err != nil {
		t.Fatalf("a device with a key of its own: %v", err)
	}
}
