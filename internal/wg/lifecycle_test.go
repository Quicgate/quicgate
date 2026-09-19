package wg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// echoWorks reports whether the connection still carries data both ways.
func echoWorks(c net.Conn) bool {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return false
	}
	_, err := c.Read(make([]byte, 1))
	return err == nil
}

// A connection that is open when a device's authorization ends, ends with it
// (QG-02), without a reload, a renewal tick or an idle timeout having to come
// along. A renewal that arrived before the deadline keeps the connection, and
// the timer of the old deadline does not close it.
func TestAnOpenConnectionEndsWithItsAuthorization(t *testing.T) {
	f := newFixture(t)
	serveTunnel(f)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	phone, laptop := newDevice(t), newDevice(t)
	first := time.Now().Add(6 * time.Second)
	a, b := phone.device(7, "10.77.0.5"), laptop.device(8, "10.77.0.6")
	a.Until, b.Until = first, first
	f.cfg.Devices = []Device{a, b}
	f.restart(t)
	phone.start(t, f, "10.77.0.5")
	laptop.start(t, f, "10.77.0.6")

	expiring, err := phone.dial(t, "10.77.0.1:80", 5*time.Second)
	if err != nil {
		t.Fatalf("the phone cannot connect: %v", err)
	}
	defer expiring.Close()
	renewed, err := laptop.dial(t, "10.77.0.1:80", 5*time.Second)
	if err != nil {
		t.Fatalf("the laptop cannot connect: %v", err)
	}
	defer renewed.Close()
	if !echoWorks(expiring) || !echoWorks(renewed) {
		t.Fatal("the connections do not work before the deadline")
	}

	// The laptop's owner is renewed in time; the phone's is not.
	b.Until = time.Now().Add(time.Hour)
	f.cfg.Devices = []Device{a, b}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(first) + 1500*time.Millisecond)

	if echoWorks(expiring) {
		t.Error("a connection opened before the deadline still carries data after it")
	}
	if st := f.m.DeviceStatus(); len(st) != 2 || st[0].Connections+st[1].Connections != 1 {
		t.Errorf("after the deadline the endpoint holds %+v, want one connection: the renewed device's", st)
	}
	if !echoWorks(renewed) {
		t.Error("the renewed device's connection was closed by the old deadline")
	}
}

// Connections to quicgate's own listeners in the tunnel count against the
// same budget as forwarded flows (QG-06): one device cannot hold more than a
// peer may hold, whatever it holds it as.
func TestTheListenerHasABudgetPerPeer(t *testing.T) {
	f := newFixture(t)
	f.cfg.Tunnel = netip.MustParsePrefix("10.77.0.0/24")
	phone := newDevice(t)
	f.cfg.Devices = []Device{phone.device(7, "10.77.0.5")}
	f.restart(t)

	f.m.mu.Lock()
	for i := 0; i < maxFlowsPerPeer; i++ {
		f.m.admitLocked("device:7", &tracked{close: func() {}})
	}
	full := f.m.roomLocked("device:7")
	other := f.m.roomLocked("device:8")
	f.m.mu.Unlock()
	if full {
		t.Fatalf("a peer with %d open connections has room for more", maxFlowsPerPeer)
	}
	if !other {
		t.Fatal("one peer at its limit leaves no room for another")
	}

	// The listener's admission uses that budget: a connection from the peer
	// that is full is closed, not handed to a handler.
	inner := &oneConnListener{conn: &addrConn{remote: "10.77.0.5:40000"}}
	ln := &peerListener{Listener: inner, m: f.m}
	if c, err := ln.Accept(); err == nil {
		c.Close()
		t.Fatal("the listener admitted a connection beyond the peer's budget")
	}
	if !inner.conn.closed {
		t.Fatal("the connection beyond the budget was not closed")
	}
}

// oneConnListener hands out one connection and then reports that it is closed.
type oneConnListener struct {
	conn *addrConn
	done bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

type addrConn struct {
	net.Conn
	remote string
	closed bool
}

func (c *addrConn) RemoteAddr() net.Addr {
	ap := netip.MustParseAddrPort(c.remote)
	return net.TCPAddrFromAddrPort(ap)
}
func (c *addrConn) Close() error { c.closed = true; return nil }

// A dial through a site that is still waiting (for a handshake, for an answer)
// is registered under the site and ends when the site is removed (QG-12),
// instead of going on until its caller gives up.
func TestRemovingASiteCancelsItsPendingDials(t *testing.T) {
	f := newFixture(t)
	// A site that never answers: nothing listens at its endpoint.
	_, pub := newKey(t)
	_, psk := newKey(t)
	silent := Site{ID: 1, Name: "silent", PublicKey: pub, PresharedKey: psk, Address: netip.MustParseAddr("10.77.0.2"),
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}, Enabled: true}
	f.cfg.Sites = []Site{silent}
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c, err := f.m.DialContext(ctx, 1, "tcp", "192.168.50.10:80")
		if err == nil {
			c.Close()
		}
		result <- err
	}()

	// The attempt is visible while it waits.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st := f.m.Status(); len(st) == 1 && st[0].Connections == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pending dial is not registered under its site: %+v", f.m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}

	f.cfg.Sites = nil
	began := time.Now()
	if err := f.m.Apply(context.Background(), f.cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !errors.Is(err, ErrNoFallback) {
			t.Fatalf("the dial ended with %v, want a refusal that is never retried outside the tunnel", err)
		}
		if took := time.Since(began); took > 3*time.Second {
			t.Fatalf("the dial ended %v after the site was removed", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial is still pending 10 s after its site was removed")
	}
	f.m.mu.Lock()
	left := len(f.m.flows["site:1"])
	f.m.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d registrations of the removed site are left", left)
	}
}
