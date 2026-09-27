package engine

import (
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// The engine's own ports: the admin listener's among them (L-23), and the
// HTTP/3 listener without early data (L-12).

// The admin port is reserved like the proxy's own, so a stream cannot be saved
// on it and race the admin server for the port at startup. The HTTP and HTTPS
// ports keep the first two places, which the admin package reads them from.
func TestReservedPortsIncludeTheAdminPort(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := New(Config{DisableTLS: true, DataDir: dir, HTTPAddr: ":80", HTTPSAddr: ":443", AdminAddr: "127.0.0.1:81"}, st)
	t.Cleanup(func() { _ = e.accessLog.Close(); _ = e.ban.closePersist() })

	ports := e.ReservedPorts()
	if len(ports) < 3 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("reserved ports %v, want 80 and 443 first", ports)
	}
	reserved := false
	for _, p := range ports {
		reserved = reserved || p == 81
	}
	if !reserved {
		t.Fatalf("reserved ports %v do not include the admin port 81", ports)
	}
	err = st.CreateStream(&store.Stream{ListenPort: 81, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 2222, Enabled: true}, e.ReservedPorts())
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("a stream on the admin port was accepted: err = %v", err)
	}
}

// The QUIC listener does not accept 0-RTT early data, which can be replayed.
func TestHTTP3ServerRefusesEarlyData(t *testing.T) {
	e, _ := newTestEngine(t)
	srv := e.newHTTP3Server(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &tls.Config{})
	if srv.QUICConfig == nil || srv.QUICConfig.Allow0RTT {
		t.Fatalf("QUIC config %+v, want one that refuses 0-RTT", srv.QUICConfig)
	}
}

// A UPnP mapping key reads back into its parts, and a key that does not is an
// error rather than port 0.
func TestParseMappingKey(t *testing.T) {
	proto, port, err := parseMappingKey(PortMapping{Proto: "TCP", Port: 443}.key())
	if err != nil || proto != "TCP" || port != 443 {
		t.Fatalf("TCP:443 read back as %q %d %v", proto, port, err)
	}
	for _, bad := range []string{"TCP", "TCP:", "TCP:x", "TCP:0", "TCP:70000", ":443"} {
		if _, _, err := parseMappingKey(bad); err == nil {
			t.Errorf("key %q was accepted", bad)
		}
	}
}
