package wg

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// udpPair returns two connected UDP sockets on loopback: what one writes, the
// other reads.
func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	reserve := func() *net.UDPAddr {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr)
	}
	a, b := reserve(), reserve()
	ca, err := net.DialUDP("udp4", a, b)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := net.DialUDP("udp4", b, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return ca, cb
}

// The forwarder delivers a datagram whole or not at all (QG-11): a relay with
// a stream-sized buffer handed the destination the first 32 KiB of a larger
// datagram as if that were the message.
func TestUDPRelayKeepsDatagramsWhole(t *testing.T) {
	device, relayIn := udpPair(t)
	relayOut, service := udpPair(t)
	for _, c := range []*net.UDPConn{device, relayIn, relayOut, service} {
		_ = c.SetReadBuffer(1 << 20)
		_ = c.SetWriteBuffer(1 << 20)
	}
	go relay(relayIn, relayOut, 5*time.Second, true)

	buf := make([]byte, maxDatagram)
	for _, size := range []int{1, 0, 1400, 32768, 32769, 40000, 65507} {
		msg := make([]byte, size)
		_, _ = rand.Read(msg)
		if _, err := device.Write(msg); err != nil {
			t.Fatalf("send %d bytes: %v", size, err)
		}
		_ = service.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := service.Read(buf)
		if err != nil {
			t.Fatalf("a datagram of %d bytes did not arrive: %v", size, err)
		}
		if n != size || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("a datagram of %d bytes arrived as %d bytes", size, n)
		}
		// And the way back.
		if _, err := service.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = device.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := device.Read(buf); err != nil || n != size || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("the reply of %d bytes arrived as %d bytes (%v)", size, n, err)
		}
	}
}
