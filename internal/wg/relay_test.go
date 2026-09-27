package wg

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// udpPair returns two connected UDP sockets on loopback: what one writes, the
// other reads.
func udpPair(t testing.TB) (*net.UDPConn, *net.UDPConn) {
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
	for _, c := range []*net.UDPConn{ca, cb} {
		_ = c.SetReadBuffer(1 << 20)
		_ = c.SetWriteBuffer(1 << 20)
	}
	return ca, cb
}

// twoStacks wires two network stacks together with a plain pipe where
// WireGuard would be: what one sends, the other receives, packet by packet
// at the tunnel's MTU. A test can then drive a stack endpoint from the
// device's side, IP fragmentation and reassembly included, without a tunnel.
func twoStacks(t testing.TB) (device, server *netStack) {
	t.Helper()
	device, err := newNetStack(netip.MustParseAddr("10.77.0.5"), mtu)
	if err != nil {
		t.Fatal(err)
	}
	server, err = newNetStack(netip.MustParseAddr("10.77.0.1"), mtu)
	if err != nil {
		device.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close(); server.Close() })
	shuttle := func(from, to *netStack) {
		bufs := [][]byte{make([]byte, mtu+64)}
		sizes := []int{0}
		for {
			n, err := from.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				_, _ = to.Write([][]byte{bufs[0][:sizes[0]]}, 0)
			}
		}
	}
	go shuttle(device, server)
	go shuttle(server, device)
	return device, server
}

// udpFlow is one forwarded UDP flow over twoStacks: the device's socket, the
// server's endpoint for the flow as CreateEndpoint would make it, and the
// LAN service the relay dials.
type udpFlow struct {
	dev     *gonet.UDPConn
	ep      tcpip.Endpoint
	wq      *waiter.Queue
	client  *gonet.UDPConn
	out     *net.UDPConn
	service *net.UDPConn
}

func newUDPFlow(t testing.TB, device, server *netStack, devPort, srvPort uint16) *udpFlow {
	t.Helper()
	f := &udpFlow{wq: new(waiter.Queue)}
	f.out, f.service = udpPair(t)
	ep, terr := server.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, f.wq)
	if terr != nil {
		t.Fatal(terr)
	}
	if terr := ep.Bind(fullAddr(netip.AddrPortFrom(server.addr, srvPort))); terr != nil {
		t.Fatal(terr)
	}
	if terr := ep.Connect(fullAddr(netip.AddrPortFrom(device.addr, devPort))); terr != nil {
		t.Fatal(terr)
	}
	f.ep = ep
	f.client = gonet.NewUDPConn(f.wq, ep)
	la, ra := fullAddr(netip.AddrPortFrom(device.addr, devPort)), fullAddr(netip.AddrPortFrom(server.addr, srvPort))
	dev, err := gonet.DialUDP(device.s, &la, &ra, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	f.dev = dev
	t.Cleanup(func() { f.dev.Close(); f.client.Close() })
	return f
}

func (f *udpFlow) relay(idle time.Duration) { go relayUDP(f.client, f.ep, f.wq, f.out, idle) }

// The forwarder delivers a datagram whole or not at all (QG-11): a relay with
// a stream-sized buffer handed the destination the first 32 KiB of a larger
// datagram as if that were the message. From the tunnel a datagram larger
// than the MTU arrives as IP fragments that the stack reassembles, and the
// relay's small tunnel-side buffer must grow for it rather than cut it.
func TestUDPRelayKeepsDatagramsWhole(t *testing.T) {
	device, server := twoStacks(t)
	f := newUDPFlow(t, device, server, 40000, 5000)
	f.relay(5 * time.Second)

	buf := make([]byte, maxDatagram)
	for _, size := range []int{1, 0, 1400, 1500, 32768, 32769, 40000, 65507} {
		msg := make([]byte, size)
		_, _ = rand.Read(msg)
		if _, err := f.dev.Write(msg); err != nil {
			t.Fatalf("send %d bytes: %v", size, err)
		}
		_ = f.service.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := f.service.Read(buf)
		if err != nil {
			t.Fatalf("a datagram of %d bytes did not arrive: %v", size, err)
		}
		if n != size || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("a datagram of %d bytes arrived as %d bytes", size, n)
		}
		// And the way back.
		if _, err := f.service.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = f.dev.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := f.dev.Read(buf); err != nil || n != size || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("the reply of %d bytes arrived as %d bytes (%v)", size, n, err)
		}
	}
	// A large datagram borrows a large buffer for itself only: once the next
	// one has been read, the flow is back to its small buffer.
	if _, err := f.dev.Write([]byte("small again")); err != nil {
		t.Fatal(err)
	}
	_ = f.service.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := f.service.Read(buf); err != nil {
		t.Fatal(err)
	}
	if n := largeBufs.taken.Load(); n > 1 {
		t.Fatalf("%d large buffers are out for one flow; one, for the LAN side, is the most a flow holds between datagrams", n)
	}
}

// Sixty-four open UDP flows hold sixty-four small buffers on the tunnel side
// and one large buffer each on the LAN side, and the relay allocates nothing
// else that grows with them (S49). Before the buffers were pooled and the
// tunnel side read into a full-size buffer, the same flows allocated twice
// that.
func TestUDPFlowsStayWithinTheRelayBufferBudget(t *testing.T) {
	const flows = 64
	device, server := twoStacks(t)
	// Sockets and endpoints first: they are not what is measured.
	all := make([]*udpFlow, flows)
	for i := range all {
		all[i] = newUDPFlow(t, device, server, uint16(40000+i), uint16(5000+i))
	}
	msg := make([]byte, 1000)
	_, _ = rand.Read(msg)
	buf := make([]byte, maxDatagram)
	largeBefore, smallBefore := largeBufs.taken.Load(), tunnelBufs.taken.Load()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for _, f := range all {
		f.relay(time.Minute)
	}
	for i, f := range all {
		if _, err := f.dev.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = f.service.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := f.service.Read(buf); err != nil || n != len(msg) {
			t.Fatalf("flow %d: %d bytes, %v", i, n, err)
		}
		if _, err := f.service.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = f.dev.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := f.dev.Read(buf); err != nil || n != len(msg) {
			t.Fatalf("flow %d, the way back: %d bytes, %v", i, n, err)
		}
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// What the flows hold by design, plus room for the stack's own packet
	// buffers and the goroutines' small objects.
	budget := uint64(flows*(tunnelBuf+maxDatagram)) + 3<<20
	if allocated > budget {
		t.Fatalf("%d UDP flows allocated %d bytes, budget %d: the relay buffers are not sized to their direction or not pooled", flows, allocated, budget)
	}
	if large := largeBufs.taken.Load() - largeBefore; large > flows {
		t.Fatalf("%d large buffers for %d flows: the tunnel side took large buffers for datagrams that fit a small one", large, flows)
	}
	if small := tunnelBufs.taken.Load() - smallBefore; small != flows {
		t.Fatalf("%d small buffers for %d flows", small, flows)
	}
	t.Logf("%d UDP flows: %d bytes allocated (%s per flow), budget %d", flows, allocated, fmt.Sprintf("%.1f KiB", float64(allocated)/flows/1024), budget)
}

// A TCP flow reads each side into a pooled stream buffer and returns it when
// the flow ends.
func TestTCPRelayReturnsItsBuffers(t *testing.T) {
	before := streamBufs.taken.Load()
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { relay(a2, b1, time.Second); close(done) }()
	go func() {
		buf := make([]byte, 5)
		_, _ = b2.Read(buf)
		_, _ = b2.Write(buf)
	}()
	_ = a1.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := a1.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := a1.Read(got); err != nil || string(got) != "hello" {
		t.Fatalf("through the relay: %q, %v", got, err)
	}
	a1.Close()
	b2.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not end when its sides were closed")
	}
	if n := streamBufs.taken.Load(); n != before {
		t.Fatalf("%d stream buffers are still out after the flow ended", n-before)
	}
}
