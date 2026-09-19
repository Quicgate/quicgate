package store

import (
	"strings"
	"sync"
	"testing"
)

// A name belongs to one host. Saving the same host several times at once (a
// Save button pressed four times) used to make four hosts with one name, of
// which the routing table served one.
func TestADomainBelongsToOneHost(t *testing.T) {
	s := openTestStore(t)
	mk := func(domains ...string) *Host {
		return &Host{Type: "dead", Domains: domains, CertMode: "none", Enabled: true}
	}
	first := mk("app.example.com", "www.example.com")
	if err := s.CreateHost(first); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*Host{
		"the same name":         mk("app.example.com"),
		"the same name, shouty": mk("APP.Example.COM"),
		"its second name":       mk("new.example.com", "www.example.com"),
		"a name listed twice":   mk("twice.example.com", "Twice.example.com"),
	} {
		if err := s.CreateHost(h); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	other := mk("other.example.com")
	if err := s.CreateHost(other); err != nil {
		t.Fatal(err)
	}
	other.Domains = []string{"other.example.com", "app.example.com"}
	if err := s.UpdateHost(other); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Errorf("an update took another host's name: %v", err)
	}
	// A host may of course keep its own names.
	first.Domains = []string{"app.example.com", "www.example.com", "third.example.com"}
	if err := s.UpdateHost(first); err != nil {
		t.Errorf("a host could not keep its own names: %v", err)
	}

	// Pressed four times at once: one host.
	var wg sync.WaitGroup
	var mu sync.Mutex
	made := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.CreateHost(mk("vpn.example.com")) == nil {
				mu.Lock()
				made++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if made != 1 {
		t.Fatalf("%d hosts were made for one name, want 1", made)
	}
}
