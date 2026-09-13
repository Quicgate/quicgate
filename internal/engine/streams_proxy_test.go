package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"quicgate/internal/store"
)

// Q08: PROXY protocol is only believed, and then required, from trusted peers.

func proxyStream(port, backend int, trusted, allowed []string) store.Stream {
	return store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: backend,
		AcceptProxyProtocol: true, TrustedProxies: trusted, AllowedCIDRs: allowed, Enabled: true}
}

func v1Header(src string, port int) string {
	return fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 5555 %d\r\n", src, port)
}

func TestProxyProtocolTrustedPeerRelaysClients(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, proxyStream(port, echoBackend(t), []string{"127.0.0.1/32"}, []string{"10.0.0.0/8"}))

	if !streamEchoes(t, port, v1Header("10.1.2.3", port)) {
		t.Fatal("trusted peer relaying an allowed client was refused")
	}
	if streamEchoes(t, port, v1Header("203.0.113.9", port)) {
		t.Fatal("trusted peer relaying a client outside the filter was admitted")
	}
	v2 := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("10.4.5.6"), Port: 5555}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	raw, err := v2.Format()
	if err != nil {
		t.Fatal(err)
	}
	if !streamEchoes(t, port, string(raw)) {
		t.Fatal("trusted peer with a v2 header for an allowed client was refused")
	}
}

func TestProxyProtocolTrustedPeerMustSendValidHeader(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, proxyStream(port, echoBackend(t), []string{"127.0.0.1/32"}, []string{"0.0.0.0/0"}))

	if streamEchoes(t, port, "") {
		t.Fatal("trusted peer without a PROXY header was forwarded")
	}
	if streamEchoes(t, port, "PROXY GARBAGE\r\n") {
		t.Fatal("trusted peer with a malformed PROXY header was forwarded")
	}
}

// A trusted peer that stalls before its header is cut off at the header
// timeout, not left holding a goroutine and socket.
func TestProxyProtocolSlowHeaderIsCutOff(t *testing.T) {
	old := proxyHeaderTimeout
	proxyHeaderTimeout = 300 * time.Millisecond
	t.Cleanup(func() { proxyHeaderTimeout = old })

	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, proxyStream(port, echoBackend(t), []string{"127.0.0.1/32"}, []string{"0.0.0.0/0"}))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("stalled trusted peer received data")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection was not closed by the server within 5s (%v)", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("server closed the stalled connection after %v, want about the %v header timeout", elapsed, proxyHeaderTimeout)
	}
}

// An untrusted peer's PROXY header is never parsed: its socket address stays
// its identity, and the header bytes are just payload.
func TestProxyProtocolUntrustedPeerHeaderIsPayload(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	backend := echoBackend(t)
	runStreams(t, e, proxyStream(port, backend, []string{"10.9.9.9/32"}, []string{"10.0.0.0/8"}))
	if streamEchoes(t, port, v1Header("10.1.2.3", port)) {
		t.Fatal("untrusted loopback peer claiming 10.1.2.3 was admitted by a 10.0.0.0/8 filter")
	}

	port2 := freeTCPPort(t)
	runStreams(t, e, proxyStream(port2, backend, []string{"10.9.9.9/32"}, []string{"127.0.0.0/8"}),
		proxyStream(port, backend, []string{"10.9.9.9/32"}, []string{"10.0.0.0/8"}))
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port2), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := v1Header("10.1.2.3", port2)
	if _, err := conn.Write([]byte(hdr)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(hdr))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("direct loopback client was not forwarded: %v", err)
	}
	if !strings.HasPrefix(string(got), "PROXY TCP4") {
		t.Fatalf("backend echoed %q, want the header bytes as ordinary payload", got)
	}
}

func TestStreamStatusReportsFailures(t *testing.T) {
	e, _ := newTestEngine(t)
	// Wildcard, like the engine's own listeners: a loopback-only socket does not
	// block a wildcard bind on Windows.
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	okPort := freeTCPPort(t)
	noTrust := freeTCPPort(t)
	runStreams(t, e,
		store.Stream{ID: 1, ListenPort: okPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, Enabled: true},
		store.Stream{ID: 2, ListenPort: noTrust, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, AcceptProxyProtocol: true, Enabled: true},
	)
	// A port held by another socket (bound on all interfaces by the engine).
	e.streams.Sync([]store.Stream{{ID: 3, ListenPort: busyPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, Enabled: true}}, nil, nil)

	byKey := map[string]StreamStatus{}
	for _, s := range e.StreamStatuses() {
		byKey[s.Key] = s
	}
	if s := byKey[fmt.Sprintf("tcp:%d", busyPort)]; s.State != "failed" || s.Error == "" {
		t.Fatalf("busy port status = %+v, want failed with the bind error", s)
	}
	// The Sync above replaced the desired set, so re-apply the first two.
	runStreams(t, e,
		store.Stream{ID: 1, ListenPort: okPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, Enabled: true},
		store.Stream{ID: 2, ListenPort: noTrust, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, AcceptProxyProtocol: true, Enabled: true},
	)
	byKey = map[string]StreamStatus{}
	for _, s := range e.StreamStatuses() {
		byKey[s.Key] = s
	}
	if s := byKey[fmt.Sprintf("tcp:%d", okPort)]; s.State != "running" || s.StreamID != 1 {
		t.Fatalf("healthy stream status = %+v, want running for stream 1", s)
	}
	if s := byKey[fmt.Sprintf("tcp:%d", noTrust)]; s.State != "failed" || !strings.Contains(s.Error, "trusted proxy") {
		t.Fatalf("PROXY stream without trusted peers status = %+v, want failed", s)
	}
}

// Q07 L4 semantics: a method-scoped allow cannot open a connection, a
// method-scoped deny still closes it.
func TestStreamACLMethodScopedRules(t *testing.T) {
	e, st := newTestEngine(t)
	getOnly := mustCreateACL(t, st, &store.AccessList{Name: "get-only", Satisfy: "any", Rules: []store.AccessRule{
		{Action: "allow", CIDR: "0.0.0.0/0", Methods: []string{"GET"}},
	}})
	denyPost := mustCreateACL(t, st, &store.AccessList{Name: "deny-post", Satisfy: "any", Rules: []store.AccessRule{
		{Action: "deny", CIDR: "127.0.0.1/32", Methods: []string{"POST"}},
		{Action: "allow", CIDR: "0.0.0.0/0"},
	}})
	backend := echoBackend(t)
	p1, p2 := freeTCPPort(t), freeTCPPort(t)
	runStreams(t, e,
		store.Stream{ListenPort: p1, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: backend, AccessListID: &getOnly, Enabled: true},
		store.Stream{ListenPort: p2, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: backend, AccessListID: &denyPost, Enabled: true},
	)
	if streamEchoes(t, p1, "") {
		t.Fatal("a GET-only allow rule opened a raw TCP stream")
	}
	if streamEchoes(t, p2, "") {
		t.Fatal("a POST-scoped deny rule did not close a raw TCP stream")
	}
}

// Q14: a TLS-terminating stream does not wait forever for a handshake.
func TestStreamTLSHandshakeTimesOut(t *testing.T) {
	old := streamHandshakeTimeout
	streamHandshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { streamHandshakeTimeout = old })

	e, st := newTestEngine(t)
	c, err := st.GenerateSelfSigned("hs", []string{"hs.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		TerminateTLS: true, CertID: &c.ID, Enabled: true})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept a silent TLS client open for 5s")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("server closed the silent TLS client after %v, want about %v", elapsed, streamHandshakeTimeout)
	}
	// Sanity: a real client still completes the handshake.
	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("real TLS client: %v", err)
	}
	_ = tc.Close()
}

// Q14: new UDP sources beyond the session cap are dropped.
func TestUDPSessionCap(t *testing.T) {
	old := udpMaxSessions
	udpMaxSessions = 2
	t.Cleanup(func() { udpMaxSessions = old })

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], addr)
		}
	}()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	e, _ := newTestEngine(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "udp", ForwardHost: "127.0.0.1",
		ForwardPort: echo.LocalAddr().(*net.UDPAddr).Port, Enabled: true})

	roundTrip := func() bool {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
		if _, err := c.Write([]byte("ping")); err != nil {
			return false
		}
		buf := make([]byte, 4)
		n, err := c.Read(buf)
		return err == nil && string(buf[:n]) == "ping"
	}
	if !roundTrip() || !roundTrip() {
		t.Fatal("the first two UDP sources should be served")
	}
	if roundTrip() {
		t.Fatal("a third UDP source was served past a cap of 2 sessions")
	}
}

// The source filter flag on its own: a spec that has a filter configured but no
// usable networks admits nobody, even if nothing marked the stream as failed.
// (buildStreamSpec also fails such a stream; each layer is tested separately.)
func TestStreamSpecFilteredWithoutNetsDenies(t *testing.T) {
	spec := &streamSpec{filtered: true}
	if spec.allowed(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}) {
		t.Fatal("a configured filter with no networks admitted a client")
	}
	open := &streamSpec{}
	if !open.allowed(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}) {
		t.Fatal("a stream with no filter configured refused a client")
	}
}
