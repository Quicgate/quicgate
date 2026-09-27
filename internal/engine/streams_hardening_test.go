package engine

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"quicgate/internal/store"
)

// Stream hardening: stable change signatures (F-1), per-source connection caps
// and idle timeouts on TCP listeners (M-14), and SNI names matched as the DNS
// names they are, whole ClientHello or not (L-32).

func echoOn(t *testing.T, conn net.Conn) error {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return fmt.Errorf("backend answered %q", buf)
	}
	return nil
}

// Two decodings of one stream, as ListStreams delivers on every reload, must
// compile to the same signature. The certificate id is a pointer; formatting
// the pointer instead of the value restarted every TLS-terminating listener,
// connections and all, on every configuration save and periodic reload.
func TestStreamSignatureIsStableAcrossDecodes(t *testing.T) {
	cert := newTestCA(t, "streams").issue(t, "stream.test", []string{"stream.test"}, x509.ExtKeyUsageServerAuth)
	loader := func(int64) (tls.Certificate, bool) { return cert, true }
	id1, id2 := int64(7), int64(7)
	a := store.Stream{ListenPort: 1000, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 22, TerminateTLS: true, CertID: &id1, Enabled: true}
	b := a
	b.CertID = &id2
	if sa, sb := buildStreamSpec(a, loader, nil).sig, buildStreamSpec(b, loader, nil).sig; sa != sb {
		t.Fatalf("the same stream decoded twice has two signatures:\n%s\n%s", sa, sb)
	}
	other := int64(8)
	b.CertID = &other
	if buildStreamSpec(a, loader, nil).sig == buildStreamSpec(b, loader, nil).sig {
		t.Fatal("a different certificate id did not change the signature")
	}
}

// A reload that changes nothing leaves the connections of a TLS-terminating
// stream alone, the way it leaves every other stream's alone.
func TestReloadKeepsTLSStreamConnections(t *testing.T) {
	e, st := newTestEngine(t)
	cert, err := st.GenerateSelfSigned("stream", []string{"stream.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	s := store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		TerminateTLS: true, CertID: &cert.ID, Enabled: true}
	if err := st.CreateStream(&s, nil); err != nil {
		t.Fatal(err)
	}
	reload(t, e)
	t.Cleanup(e.streams.StopAll)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true, ServerName: "stream.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := echoOn(t, conn); err != nil {
		t.Fatalf("control: %v", err)
	}
	// Each reload reads the stream from the database afresh.
	reload(t, e)
	reload(t, e)
	if err := echoOn(t, conn); err != nil {
		t.Fatalf("a reload that changed nothing cut the connection: %v", err)
	}
}

// One client address cannot take every slot of a TCP listener: its connections
// are capped, other clients are still served, and a closed connection frees
// its place.
func TestTCPStreamPerSourceCap(t *testing.T) {
	old := tcpMaxConnsPerIP
	tcpMaxConnsPerIP = 2
	t.Cleanup(func() { tcpMaxConnsPerIP = old })

	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true})

	dial := func(from string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		if from != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		c, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		return c, err
	}
	mustDial := func(from string) net.Conn {
		t.Helper()
		c, err := dial(from)
		if err != nil {
			t.Fatalf("dial from %q: %v", from, err)
		}
		return c
	}
	first, second := mustDial(""), mustDial("")
	if echoOn(t, first) != nil || echoOn(t, second) != nil {
		t.Fatal("the first two connections from one address should be served")
	}
	if echoOn(t, mustDial("")) == nil {
		t.Fatal("a third connection from the same address was served past its cap")
	}
	if other, err := dial("127.0.0.2"); err != nil {
		t.Logf("cannot connect from 127.0.0.2 on this system, skipping that check: %v", err)
	} else if err := echoOn(t, other); err != nil {
		t.Fatalf("a client from another address was locked out by the first address's connections: %v", err)
	}
	_ = first.Close()
	waitUntil(t, func() bool { return echoOn(t, mustDial("")) == nil }, "a closed connection to free its place")
}

// A TCP connection that carries nothing for the idle timeout is closed with
// its backend; one that keeps talking stays.
func TestTCPStreamIdleConnectionIsClosed(t *testing.T) {
	old := tcpIdleTimeout
	tcpIdleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { tcpIdleTimeout = old })

	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// An exchange every 100 ms is well within the idle period: the deadline
	// moves with the traffic.
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := echoOn(t, conn); err != nil {
			t.Fatalf("exchange %d: an active connection was closed: %v", i, err)
		}
	}
	// Then silence: the listener closes it after the idle timeout.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("received data on an idle connection")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("an idle connection was still open after %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the idle connection was closed after %v, want about %v", elapsed, tcpIdleTimeout)
	}
}

// clientHello builds a minimal ClientHello handshake message, record layer
// not included, naming sni in a server_name extension (none when sni is "").
func clientHello(sni string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // client_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id: empty
	body = append(body, 0, 2, 0x13, 0x01)    // cipher_suites: one
	body = append(body, 1, 0)                // compression_methods: null
	var exts []byte
	if sni != "" {
		name := []byte(sni)
		entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
		list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
		exts = append(exts, 0, 0, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// tlsRecords wraps a handshake message in handshake records of at most n bytes.
func tlsRecords(b []byte, n int) []byte {
	var out []byte
	for len(b) > 0 {
		chunk := b
		if len(chunk) > n {
			chunk = b[:n]
		}
		out = append(out, 0x16, 0x03, 0x01, byte(len(chunk)>>8), byte(len(chunk)))
		out = append(out, chunk...)
		b = b[len(chunk):]
	}
	return out
}

// peekWire runs peekSNI over a pipe that delivers wire.
func peekWire(t *testing.T, wire []byte) (string, []byte, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() { _, _ = client.Write(wire) }()
	sni, buf, err := peekSNI(server)
	_ = server.Close()
	if buf == nil {
		return sni, nil, err
	}
	return sni, buf.Bytes(), err
}

// A ClientHello split over several records is read whole, and every byte of
// it is replayed to the backend.
func TestPeekSNIReadsFragmentedClientHello(t *testing.T) {
	hello := clientHello("a.test")
	for _, size := range []int{len(hello), 40, 3} {
		wire := tlsRecords(hello, size)
		if len(wire)/(size+5) > sniMaxRecords {
			// Only sizes within the record bound are expected to work.
			continue
		}
		sni, got, err := peekWire(t, wire)
		if err != nil {
			t.Fatalf("records of %d bytes: %v", size, err)
		}
		if sni != "a.test" {
			t.Fatalf("records of %d bytes: server name %q, want a.test", size, sni)
		}
		if !bytes.Equal(got, wire) {
			t.Fatalf("records of %d bytes: %d bytes kept for the backend, want all %d", size, len(got), len(wire))
		}
	}
	if _, _, err := peekWire(t, tlsRecords(hello, 1)); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("a ClientHello over more than %d records: err = %v, want a refusal", sniMaxRecords, err)
	}
}

// Whatever is not a ClientHello is refused, not routed to the default backend.
func TestPeekSNIRefusesNonClientHello(t *testing.T) {
	serverHello := clientHello("a.test")
	serverHello[0] = 0x02
	if _, _, err := peekWire(t, tlsRecords(serverHello, len(serverHello))); err == nil {
		t.Fatal("a ServerHello as the first message was accepted")
	}
	if _, _, err := peekWire(t, []byte("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("plain HTTP was accepted as TLS")
	}
}

// A server name is a DNS name: the route for a.test matches A.TEST and
// a.test. as well, however the route itself was written.
func TestSNIRoutesMatchWithoutCaseOrTrailingDot(t *testing.T) {
	spec := buildStreamSpec(store.Stream{ListenPort: 443, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 8443, Enabled: true,
		SNIRoutes: []store.SNIRoute{{Host: "A.Test.", ForwardHost: "10.0.0.1", ForwardPort: 443}}}, nil, nil)
	for _, name := range []string{"a.test", "A.TEST", "a.test.", "A.Test."} {
		sni, _, err := peekWire(t, tlsRecords(clientHello(name), 16384))
		if err != nil {
			t.Fatal(err)
		}
		if dest := spec.tcp.sniRoutes[routeName(sni)]; dest != "10.0.0.1:443" {
			t.Fatalf("server name %q routed to %q, want 10.0.0.1:443", name, dest)
		}
	}
	if dest := spec.tcp.sniRoutes[routeName("b.test")]; dest != "" {
		t.Fatalf("an unrelated name matched %q", dest)
	}
	dup := buildStreamSpec(store.Stream{ListenPort: 443, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 8443, Enabled: true,
		SNIRoutes: []store.SNIRoute{{Host: "a.test", ForwardHost: "10.0.0.1", ForwardPort: 443}, {Host: "A.TEST", ForwardHost: "10.0.0.2", ForwardPort: 443}}}, nil, nil)
	if len(dup.warnings) != 1 || !strings.Contains(dup.warnings[0], "same server") {
		t.Fatalf("two routes for one name gave warnings %v, want one about the duplicate", dup.warnings)
	}
}

// The same through a live passthrough listener: the certificate that comes
// back proves which backend answered.
func TestSNIPassthroughRoutesNamesCaseInsensitively(t *testing.T) {
	ca := newTestCA(t, "sni")
	certA := ca.issue(t, "a.test", []string{"a.test"}, x509.ExtKeyUsageServerAuth)
	leafA, err := x509.ParseCertificate(certA.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	lnA, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certA}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnA.Close() })
	go func() {
		for {
			c, err := lnA.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true,
		SNIRoutes: []store.SNIRoute{{Host: "A.Test", ForwardHost: "127.0.0.1", ForwardPort: lnA.Addr().(*net.TCPAddr).Port}}})

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true, ServerName: "a.TEST"})
	if err != nil {
		t.Fatalf("a client naming a.TEST did not reach the a.test backend: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().PeerCertificates[0]; !got.Equal(leafA) {
		t.Fatalf("a client naming a.TEST got the certificate of %q, want a.test's", got.Subject.CommonName)
	}
	if err := echoOn(t, conn); err != nil {
		t.Fatalf("passthrough connection: %v", err)
	}
}

// The idle timeout is about the connection, not one direction: a download
// that keeps flowing while the client says nothing for longer than the idle
// period (a video, a large file) is not cut off. Only silence both ways is.
func TestTCPStreamOneWayTrafficIsNotIdle(t *testing.T) {
	old := tcpIdleTimeout
	tcpIdleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { tcpIdleTimeout = old })

	// A backend that sends a byte every 50 ms for 1.5 s. It also watches its
	// read side: the client never sends anything, so the only thing it can see
	// there is quicgate ending the client's direction (a FIN), which many
	// servers take as "the client is done" and hang up on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const total = 30
	sending := make(chan struct{})
	endedEarly := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		go func() {
			_, err := c.Read(make([]byte, 1))
			select {
			case <-sending:
				endedEarly <- false // the backend was done first
			default:
				endedEarly <- err != nil
			}
		}()
		defer close(sending)
		for i := 0; i < total; i++ {
			if _, err := c.Write([]byte{'x'}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1",
		ForwardPort: ln.Addr().(*net.TCPAddr).Port, Enabled: true})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(io.LimitReader(conn, total))
	if len(got) != total {
		t.Fatalf("the download was cut off after %d of %d bytes (%v): one silent direction ended the connection", len(got), total, err)
	}
	select {
	case early := <-endedEarly:
		if early {
			t.Fatal("the backend saw the client's direction end while it was still sending: a silent direction was closed on its own")
		}
	default:
	}
}
