package engine

import (
	"net"
	"testing"
	"time"
)

// Addresses on the never-ban list collect refusals without ever being banned,
// and putting a banned address on the list lets it in straight away.
func TestNeverBanList(t *testing.T) {
	cfg := banConfig{enabled: true, threshold: 2, window: time.Hour, banFor: time.Hour}
	b := newBanManager(func() banConfig { return cfg }, nil)
	fail := func(ip string) {
		for i := 0; i < 3; i++ {
			b.recordFailure(net.JoinHostPort(ip, "40000"), "acl.test", "address not allowed")
		}
	}

	var err error
	if cfg.exempt, err = ParseBanExempt("203.0.113.5, 2001:db8:1::/48\n10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.5", "2001:db8:1::7", "10.20.30.40", "::ffff:203.0.113.5"} {
		fail(ip)
		if b.blocked(net.JoinHostPort(ip, "40000")) {
			t.Errorf("%s is on the never-ban list and was banned", ip)
		}
	}
	fail("203.0.113.6")
	if !b.blocked("203.0.113.6:40000") {
		t.Fatal("an address next to a listed one was not banned")
	}

	// Listing a banned address lifts its ban, and the list of bans drops it.
	cfg.exempt, _ = ParseBanExempt("203.0.113.6")
	b.liftExempt()
	if n := len(b.list(nil)); n != 0 {
		t.Fatalf("%d bans listed after the banned address was put on the never-ban list, want 0", n)
	}
	if b.blocked("203.0.113.6:40000") {
		t.Fatal("a banned address put on the never-ban list is still refused")
	}
}

// "Never ban my own addresses" covers the interfaces and the router's public
// address, only while it is switched on, and follows a new public address.
func TestNeverBanOwnAddresses(t *testing.T) {
	cfg := banConfig{enabled: true, threshold: 1, window: time.Hour, banFor: time.Hour, exemptOwn: true}
	b := newBanManager(func() banConfig { return cfg }, nil)
	public := "198.51.100.20"
	b.own = newOwnAddresses(func() string { return public })
	b.own.ifaces = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.54"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	banned := func(ip string) bool {
		b.recordFailure(ip+":40000", "acl.test", "address not allowed")
		return b.blocked(ip + ":40000")
	}

	if banned("198.51.100.20") || banned("192.168.1.54") {
		t.Fatal("an own address was banned with the setting on")
	}
	if !banned("192.168.1.55") {
		t.Fatal("another host on the LAN was not banned: only the machine's own address is covered")
	}
	if got := b.own.list(); len(got) != 2 || got[0] != (OwnAddress{IP: "198.51.100.20", Source: "router"}) || got[1] != (OwnAddress{IP: "192.168.1.54", Source: "interface"}) {
		t.Fatalf("own addresses = %+v, want the router's address then the interface's", got)
	}

	// The router gets a new public address: the old one is a stranger again.
	public = "198.51.100.99"
	b.own.at = time.Time{} // the cached addresses are old
	if banned("198.51.100.99") {
		t.Fatal("the new public address was banned")
	}
	if !banned("198.51.100.20") {
		t.Fatal("the previous public address is still treated as our own")
	}

	cfg.exemptOwn = false
	if !banned("198.51.100.99") {
		t.Fatal("the own address was not banned with the setting off")
	}
}

func TestParseBanExemptRefusesTypos(t *testing.T) {
	for _, bad := range []string{"203.0.113", "10.0.0.0/33", "home", "203.0.113.5/24x"} {
		if _, err := ParseBanExempt("192.0.2.1\n" + bad); err == nil {
			t.Errorf("ParseBanExempt accepted %q", bad)
		}
	}
	if got, err := ParseBanExempt(" \n"); err != nil || len(got) != 0 {
		t.Fatalf("an empty list = %v, %v", got, err)
	}
}
