package store

import (
	"strings"
	"testing"
)

// Q08: accepting PROXY protocol needs the peers whose header is believed.
func TestStreamAcceptProxyNeedsTrustedPeers(t *testing.T) {
	base := func() Stream {
		return Stream{ListenPort: 2525, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 25, AcceptProxyProtocol: true}
	}

	s := base()
	if err := s.Validate(nil, nil); err == nil || !strings.Contains(err.Error(), "trusted proxy") {
		t.Fatalf("accept without trusted peers: got %v, want a trusted-proxy error", err)
	}

	s = base()
	s.TrustedProxies = []string{"not-an-address"}
	if err := s.Validate(nil, nil); err == nil {
		t.Fatal("an unparsable trusted proxy was accepted")
	}

	s = base()
	s.TrustedProxies = []string{"10.0.0.5", "2001:db8::1", "192.168.1.0/24"}
	if err := s.Validate(nil, nil); err != nil {
		t.Fatalf("valid trusted proxies rejected: %v", err)
	}
	want := []string{"10.0.0.5/32", "2001:db8::1/128", "192.168.1.0/24"}
	for i := range want {
		if s.TrustedProxies[i] != want[i] {
			t.Fatalf("trusted proxy %d normalised to %q, want %q", i, s.TrustedProxies[i], want[i])
		}
	}

	// Without PROXY accept the list has no meaning and is dropped.
	s = base()
	s.AcceptProxyProtocol = false
	s.TrustedProxies = []string{"10.0.0.5"}
	if err := s.Validate(nil, nil); err != nil || s.TrustedProxies != nil {
		t.Fatalf("trusted proxies without accept: err=%v list=%v, want accepted and cleared", err, s.TrustedProxies)
	}

	// The field round-trips through the database.
	st := openTestStore(t)
	s = base()
	s.TrustedProxies = []string{"10.0.0.5"}
	s.Enabled = true
	if err := st.CreateStream(&s, nil); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListStreams()
	if err != nil || len(list) != 1 || len(list[0].TrustedProxies) != 1 || list[0].TrustedProxies[0] != "10.0.0.5/32" {
		t.Fatalf("stored stream trusted proxies = %v (err %v)", list, err)
	}
}
