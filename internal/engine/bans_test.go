package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quicgate/internal/store"
)

// The ban list says who is banned, for which host and why, and a ban can be
// lifted by hand.
func TestBansShowWhoAndWhy(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	lan := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all", Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	vault := mustCreateACL(t, st, &store.AccessList{Name: "vault", Satisfy: "all", Users: []store.AccessUser{{Username: "family", Password: "right"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"acl.test"}, Upstream: up, AccessListID: &lan})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"vault.test"}, Upstream: up, AccessListID: &vault})
	reload(t, e)
	e.banCfg.Store(&banConfig{enabled: true, threshold: 2, window: time.Hour, banFor: time.Hour})

	serve := e.ban.wrap(e.accessLog.wrap(e.serveHTTPS))
	do := func(host, ip, auth string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = ip + ":40000"
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		serve(rr, r)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}
	for i := 0; i < 2; i++ {
		do("acl.test", "203.0.113.5", "")
	}
	time.Sleep(5 * time.Millisecond)
	for i := 0; i < 2; i++ {
		do("vault.test:8443", "198.51.100.7", basic("family", "wrong")) // the port is not part of the host shown
	}

	bans := e.Bans()
	if len(bans) != 2 {
		t.Fatalf("%d bans, want 2: %+v", len(bans), bans)
	}
	want := []BanInfo{
		{IP: "198.51.100.7", Host: "vault.test", Reason: `wrong credentials for access list "vault"`, Failures: 2},
		{IP: "203.0.113.5", Host: "acl.test", Reason: `address not allowed by access list "lan"`, Failures: 2},
	}
	for i, w := range want {
		b := bans[i]
		if b.IP != w.IP || b.Host != w.Host || b.Reason != w.Reason || b.Failures != w.Failures {
			t.Fatalf("ban %d = %+v, want %+v (newest first)", i, b, w)
		}
		if d := b.Until.Sub(b.Since); d != time.Hour {
			t.Fatalf("ban %d lasts %v, want 1h", i, d)
		}
	}

	if !e.Unban("203.0.113.5") {
		t.Fatal("unban of a banned address reported it was not banned")
	}
	if e.Unban("203.0.113.5") {
		t.Fatal("a second unban reported the address was still banned")
	}
	if code, body := do("acl.test", "203.0.113.5", ""); code != http.StatusForbidden || body == "temporarily banned" {
		t.Fatalf("after unban: %d %q, want the access list's own 403", code, body)
	}
	if n := len(e.Bans()); n != 1 {
		t.Fatalf("%d bans after lifting one, want 1", n)
	}

	e.banCfg.Store(&banConfig{})
	if n := len(e.Bans()); n != 0 {
		t.Fatalf("%d bans listed with auto-ban off, want 0", n)
	}
}

// Bans survive a restart: they are saved when they change and restored at
// start, without the ones that expired or were lifted.
func TestBansSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := banConfig{enabled: true, threshold: 1, window: time.Hour, banFor: time.Hour}
	first := newBanManager(func() banConfig { return cfg }, nil)
	first.persistTo(filepath.Join(dir, "bans.json"))
	first.recordFailure("203.0.113.5:1", "acl.test", `address not allowed by access list "lan"`)
	first.recordFailure("198.51.100.7:1", "vault.test", `wrong credentials for access list "vault"`)
	waitUntil(t, func() bool {
		data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
		return strings.Contains(string(data), "203.0.113.5") && strings.Contains(string(data), "198.51.100.7")
	}, "both bans to be saved")
	first.unban("198.51.100.7")
	// Lifting a ban is saved straight away too, not only at shutdown.
	waitUntil(t, func() bool {
		data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
		return strings.Contains(string(data), "203.0.113.5") && !strings.Contains(string(data), "198.51.100.7")
	}, "the lifted ban to leave the saved file")
	if err := first.closePersist(); err != nil {
		t.Fatal(err)
	}

	second := newBanManager(func() banConfig { return cfg }, nil)
	second.persistTo(filepath.Join(dir, "bans.json"))
	t.Cleanup(func() { _ = second.closePersist() })
	bans := second.list(nil)
	if len(bans) != 1 || bans[0].IP != "203.0.113.5" || bans[0].Host != "acl.test" || bans[0].Reason != `address not allowed by access list "lan"` {
		t.Fatalf("after a restart: %+v, want only the ban on 203.0.113.5 with its host and reason", bans)
	}
	if !second.blocked("203.0.113.5:40000") || second.blocked("198.51.100.7:40000") {
		t.Fatal("after a restart the restored ban does not apply, or the lifted one came back")
	}

	// A new ban is saved without waiting for shutdown.
	second.recordFailure("192.0.2.44:1", "dns.test", "address not allowed")
	waitUntil(t, func() bool {
		data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
		return strings.Contains(string(data), "192.0.2.44")
	}, "the new ban to be saved")
}

// Saved bans that expired, or entries that hold no address, are not restored.
func TestSavedBansAreValidated(t *testing.T) {
	dir := t.TempDir()
	future, past := time.Now().Add(time.Hour).UTC().Format(time.RFC3339), time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	doc := `{"version":1,"bans":[` +
		`{"ip":"203.0.113.5","since":"` + past + `","until":"` + future + `","failures":5,"host":"a.test","reason":"r"},` +
		`{"ip":"203.0.113.6","since":"` + past + `","until":"` + past + `","failures":5,"host":"a.test","reason":"expired"},` +
		`{"ip":"not-an-address","since":"` + past + `","until":"` + future + `","failures":5,"host":"a.test","reason":"bad"}]}`
	if err := os.WriteFile(filepath.Join(dir, "bans.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newBanManager(func() banConfig { return banConfig{enabled: true} }, nil)
	b.persistTo(filepath.Join(dir, "bans.json"))
	t.Cleanup(func() { _ = b.closePersist() })
	if bans := b.list(nil); len(bans) != 1 || bans[0].IP != "203.0.113.5" {
		t.Fatalf("restored %+v, want only 203.0.113.5", bans)
	}
}

// The reason names what failed: the address, the credentials, or both.
func TestAccessListRefusalReasons(t *testing.T) {
	list := &compiledAccess{name: "home", users: map[string]string{"u": "x"}}
	withAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	withAuth.Header.Set("Authorization", basic("u", "bad"))
	without := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range []struct {
		list         *compiledAccess
		r            *http.Request
		ipOK, authOK bool
		want         string
	}{
		{&compiledAccess{name: "home"}, without, false, true, `address not allowed by access list "home"`},
		{list, without, true, false, `no credentials for access list "home"`},
		{list, withAuth, true, false, `wrong credentials for access list "home"`},
		{list, withAuth, false, false, `address not allowed and wrong credentials for access list "home"`},
		{list, withAuth, false, true, `address not allowed by access list "home"`},
	} {
		if got := c.list.refusalReason(c.r, c.ipOK, c.authOK); got != c.want {
			t.Errorf("refusalReason(ip %v, auth %v) = %q, want %q", c.ipOK, c.authOK, got, c.want)
		}
	}
}
