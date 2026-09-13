package engine

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"quicgate/internal/store"
)

// A connection is admitted under the stream's configuration at the time. When
// that configuration changes (a source restriction added, the stream disabled),
// connections admitted under the old one end with it, the way every new HTTP
// request is checked against the current rules. A change to another stream
// leaves them alone.
func TestStreamChangeClosesConnectionsItAdmitted(t *testing.T) {
	e, _ := newTestEngine(t)
	port := freeTCPPort(t)
	s := store.Stream{ID: 1, ListenPort: port, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true}
	runStreams(t, e, s)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func() bool {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			return false
		}
		buf := make([]byte, 4)
		_, err := io.ReadFull(conn, buf)
		return err == nil && string(buf) == "ping"
	}
	if !echo() {
		t.Fatal("control: the open connection did not echo")
	}

	// Another stream changes: this connection is untouched.
	other := store.Stream{ID: 2, ListenPort: freeTCPPort(t), Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echoBackend(t), Enabled: true}
	e.SetDockerRoutes(nil, []store.Stream{s, other})
	if !echo() {
		t.Fatal("a change to a different stream closed this stream's connection")
	}

	// This stream now admits only 10.0.0.0/8, which excludes the open connection.
	s.AllowedCIDRs = []string{"10.0.0.0/8"}
	e.SetDockerRoutes(nil, []store.Stream{s, other})
	if streamEchoes(t, port, "") {
		t.Fatal("a new connection from outside the restriction was forwarded")
	}
	if echo() {
		t.Fatal("a connection admitted before the restriction still reaches the backend")
	}
}
