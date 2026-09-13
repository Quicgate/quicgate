package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"quicgate/internal/store"
)

// Stream fail-closed tests drive real TCP listeners through Engine.Reload, so
// they cover the same compile step and forwarder the live proxy uses.

func echoBackend(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// streamEchoes connects to the stream, optionally writes a preamble (a PROXY
// header), sends "ping" and reports whether "ping" came back from the backend.
func streamEchoes(t *testing.T, port int, preamble string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return false // refused: nothing listens
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(preamble + "ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return string(buf) == "ping"
}

func runStreams(t *testing.T, e *Engine, streams ...store.Stream) {
	t.Helper()
	e.SetDockerRoutes(nil, streams)
	t.Cleanup(e.streams.StopAll)
}

// Control: a plain stream forwards.
func TestStreamControlForwards(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true})
	if !streamEchoes(t, port, "") {
		t.Fatal("control stream did not forward")
	}
}

// Q07: TLS termination whose certificate is missing must not quietly become a
// plaintext forwarder.
func TestStreamMissingTLSCertDoesNotForwardPlaintext(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	missing := int64(999999)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		TerminateTLS: true, CertID: &missing, Enabled: true})
	if streamEchoes(t, port, "") {
		t.Fatal("stream with an unavailable TLS certificate forwarded plaintext")
	}
}

// Q07: an access list reused as a stream filter keeps its ordered deny rules.
func TestStreamACLOrderedDenyApplies(t *testing.T) {
	e, st := newTestEngine(t)
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "deny-loopback", Satisfy: "any", Rules: []store.AccessRule{
		{Action: "deny", CIDR: "127.0.0.1/32"},
		{Action: "allow", CIDR: "0.0.0.0/0"},
	}})
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		AccessListID: &aclID, Enabled: true})
	if streamEchoes(t, port, "") {
		t.Fatal("stream admitted a client its access list denies")
	}
}

// Q07: an access list whose only rule does not resolve must not leave the
// stream unrestricted.
func TestStreamACLWithNothingUsableIsClosed(t *testing.T) {
	e, st := newTestEngine(t)
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "ddns", Satisfy: "any", Rules: []store.AccessRule{
		{Action: "allow", Host: unresolvableHost},
	}})
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		AccessListID: &aclID, Enabled: true})
	if streamEchoes(t, port, "") {
		t.Fatal("stream with an access list that resolves to nothing admitted a client")
	}
}

// Q07: a list that needs basic-auth credentials cannot be satisfied at L4.
func TestStreamACLNeedingCredentialsIsClosed(t *testing.T) {
	e, st := newTestEngine(t)
	aclID := mustCreateACL(t, st, &store.AccessList{Name: "users", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "0.0.0.0/0"}},
		Users: []store.AccessUser{{Username: "u", Password: "p"}}})
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		AccessListID: &aclID, Enabled: true})
	if streamEchoes(t, port, "") {
		t.Fatal("stream admitted a client past a list that requires credentials it cannot check")
	}
}

// Q07: a source filter whose entries all fail to parse is still a filter.
func TestStreamInvalidInlineCIDRsAreClosed(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		AllowedCIDRs: []string{"not-a-cidr"}, Enabled: true})
	if streamEchoes(t, port, "") {
		t.Fatal("stream with an unparsable source filter admitted a client")
	}
}

// Q08: a client that connects directly cannot pick its own identity by
// sending a PROXY header.
func TestStreamProxyProtocolFromUntrustedPeerIsNotBelieved(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	runStreams(t, e, store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		AcceptProxyProtocol: true, AllowedCIDRs: []string{"10.0.0.0/8"}, Enabled: true})
	header := fmt.Sprintf("PROXY TCP4 10.1.2.3 127.0.0.1 5555 %d\r\n", port)
	if streamEchoes(t, port, header) {
		t.Fatal("a loopback client claiming 10.1.2.3 in a PROXY header was admitted by a 10.0.0.0/8 filter")
	}
}

// Q07: replacing a stream's certificate takes effect for new connections.
func TestStreamCertificateReplacementApplies(t *testing.T) {
	e, st := newTestEngine(t)
	first, err := st.GenerateSelfSigned("stream-a", []string{"stream.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.GenerateSelfSigned("stream-b", []string{"stream.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	stream := store.Stream{ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t),
		TerminateTLS: true, CertID: &first.ID, Enabled: true}
	runStreams(t, e, stream)

	leaf := func() *x509.Certificate {
		t.Helper()
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port),
			&tls.Config{InsecureSkipVerify: true, ServerName: "stream.test"})
		if err != nil {
			t.Fatalf("tls dial: %v", err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0]
	}
	before := leaf()

	certPEM, keyPEM, err := st.GetCustomCertPEM(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCustomCertPEM(first.ID, &store.CustomCert{Name: "stream-a", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("replace certificate: %v", err)
	}
	reload(t, e)
	after := leaf()
	if before.Equal(after) {
		t.Fatal("stream still presents the replaced certificate after reload")
	}
}
