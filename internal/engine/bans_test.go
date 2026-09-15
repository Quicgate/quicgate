package engine

import (
	"net/http"
	"net/http/httptest"
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
