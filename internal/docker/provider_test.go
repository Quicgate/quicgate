package docker

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"quicgate/internal/store"
)

// applied records what the provider handed to the engine.
type applied struct {
	mu      sync.Mutex
	calls   int
	hosts   []store.Host
	streams []store.Stream
	changed chan struct{}
}

func (a *applied) apply(h []store.Host, s []store.Stream) {
	a.mu.Lock()
	a.calls++
	a.hosts, a.streams = h, s
	a.mu.Unlock()
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

func (a *applied) domains() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, h := range a.hosts {
		out = append(out, h.Domains...)
	}
	return out
}

func (a *applied) ports() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []int
	for _, s := range a.streams {
		out = append(out, s.ListenPort)
	}
	return out
}

// aggProvider builds a provider with one endpoint whose derivations are given
// directly, so aggregation can be tested without a daemon.
func aggProvider(raw []rawDerived, existing func() map[string]bool, used func() map[int]bool) (*Provider, *applied) {
	a := &applied{changed: make(chan struct{}, 1)}
	p := &Provider{
		opts:            Options{LabelPrefix: "quicgate"},
		apply:           a.apply,
		existingDomains: existing,
		usedPorts:       used,
		reaggregate:     reaggregateEvery,
		adoptable:       map[string]adopted{},
		eps: []*epState{{
			cfg:       Endpoint{Name: "local", Connect: "/var/run/docker.sock", Address: "127.0.0.1"},
			connected: true,
			raw:       raw,
		}},
	}
	return p, a
}

func dockerHost(domains ...string) *store.Host {
	return &store.Host{Type: "proxy", Domains: domains, CertMode: "auto", ForceSSL: true, Enabled: true,
		Upstream: store.Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}
}

func statusOf(p *Provider, name string) ContainerStatus {
	for _, c := range p.Status().Containers {
		if c.Name == name {
			return c
		}
	}
	return ContainerStatus{}
}

func containsWarning(st ContainerStatus, sub string) bool {
	for _, w := range st.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// Manual hosts always win: also when the manual host is a wildcard that covers
// the container's exact name (the routing table prefers an exact name, so the
// container would otherwise take that traffic from *.example.com and have a
// certificate issued for it), and also when the manual host is disabled
// (ExistingDomains lists configured names, served or not).
func TestAggregateManualWildcardAndDisabledHostWin(t *testing.T) {
	raw := []rawDerived{
		{name: "api", host: dockerHost("api.example.com", "api.other.test")},
		{name: "star", host: dockerHost("*.example.com")},
		{name: "off", host: dockerHost("paused.example.org")},
		{name: "free", host: dockerHost("free.example.org")},
	}
	// paused.example.org is a manual host that happens to be disabled; the hook
	// lists it all the same.
	existing := func() map[string]bool {
		return map[string]bool{"*.example.com": true, "paused.example.org": true}
	}
	p, a := aggProvider(raw, existing, nil)
	p.aggregate()

	got := strings.Join(a.domains(), " ")
	if got != "api.other.test free.example.org" {
		t.Fatalf("applied domains = %q, want only api.other.test and free.example.org", got)
	}
	api := statusOf(p, "api")
	if !api.Routed || len(api.Domains) != 1 || api.Domains[0] != "api.other.test" {
		t.Fatalf("api status = %+v", api)
	}
	if !containsWarning(api, "api.example.com is covered by the manual wildcard host *.example.com") {
		t.Fatalf("api warnings = %v", api.Warnings)
	}
	if star := statusOf(p, "star"); star.Routed || !containsWarning(star, "*.example.com is configured on a manual host") {
		t.Fatalf("star status = %+v", star)
	}
	if off := statusOf(p, "off"); off.Routed || !containsWarning(off, "paused.example.org is configured on a manual host") {
		t.Fatalf("off status = %+v", off)
	}
	if free := statusOf(p, "free"); !free.Routed || len(free.Warnings) != 0 {
		t.Fatalf("free status = %+v", free)
	}
}

// A container's stream that would collide with a manual stream, with a port
// quicgate listens on, or with another container's stream is skipped, and its
// status says so instead of claiming it is routed; the engine used to drop it
// with a log line only.
func TestAggregateStreamCollisionsAreReported(t *testing.T) {
	mk := func(port int, proto string) store.Stream {
		return store.Stream{ListenPort: port, Protocol: proto, ForwardHost: "127.0.0.1", ForwardPort: port, Enabled: true}
	}
	raw := []rawDerived{
		{name: "a", streams: []store.Stream{mk(25565, "tcp"), mk(443, "tcp"), mk(5432, "tcp")}},
		{name: "b", streams: []store.Stream{mk(25565, "udp"), mk(2222, "tcp")}},
	}
	used := func() map[int]bool { return map[int]bool{443: true, 5432: true} }
	p, a := aggProvider(raw, func() map[string]bool { return nil }, used)
	p.aggregate()

	if ports := a.ports(); len(ports) != 2 || ports[0] != 25565 || ports[1] != 2222 {
		t.Fatalf("applied stream ports = %v, want [25565 2222]", ports)
	}
	sa := statusOf(p, "a")
	if !sa.Routed || len(sa.Streams) != 1 || !strings.HasPrefix(sa.Streams[0], "25565/tcp") {
		t.Fatalf("a status = %+v", sa)
	}
	if !containsWarning(sa, "listen port 443 belongs to a manual stream or to quicgate itself (skipped)") ||
		!containsWarning(sa, "listen port 5432 belongs to a manual stream or to quicgate itself (skipped)") {
		t.Fatalf("a warnings = %v", sa.Warnings)
	}
	sb := statusOf(p, "b")
	if !containsWarning(sb, "stream 25565/udp: listen port 25565 is already claimed by container local/a (skipped)") {
		t.Fatalf("b warnings = %v", sb.Warnings)
	}
	if len(sb.Streams) != 1 || !strings.HasPrefix(sb.Streams[0], "2222/tcp") {
		t.Fatalf("b streams = %v", sb.Streams)
	}
	// What is offered for adoption is what is routed.
	if _, streams, ok := p.Adopt("local", "a"); !ok || len(streams) != 1 || streams[0].ListenPort != 25565 {
		t.Fatalf("adoptable streams of a = %+v %v", streams, ok)
	}
}

// The routes are aggregated again on a timer, so a manual host created or
// deleted without any container event takes or frees its name; the engine is
// only reloaded when the set changed.
func TestPeriodicReaggregationFollowsManualHosts(t *testing.T) {
	var mu sync.Mutex
	manual := map[string]bool{}
	existing := func() map[string]bool {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]bool{}
		for k := range manual {
			out[k] = true
		}
		return out
	}
	p, a := aggProvider([]rawDerived{{name: "app", host: dockerHost("app.example.com")}}, existing, nil)
	p.reaggregate = 10 * time.Millisecond
	p.aggregate()
	if got := a.domains(); len(got) != 1 {
		t.Fatalf("initial domains = %v", got)
	}
	<-a.changed

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.runPeriodic(ctx); close(done) }()

	// A manual host takes the name: the next tick withdraws the container's route.
	mu.Lock()
	manual["app.example.com"] = true
	mu.Unlock()
	select {
	case <-a.changed:
	case <-time.After(3 * time.Second):
		t.Fatal("the manual host was not noticed by the timer-driven aggregation")
	}
	if got := a.domains(); len(got) != 0 {
		t.Fatalf("domains after the manual host appeared = %v, want none", got)
	}
	if st := statusOf(p, "app"); st.Routed || !containsWarning(st, "configured on a manual host") {
		t.Fatalf("status after the manual host appeared = %+v", st)
	}

	// Unchanged rounds do not reload the engine.
	a.mu.Lock()
	calls := a.calls
	a.mu.Unlock()
	time.Sleep(60 * time.Millisecond)
	a.mu.Lock()
	again := a.calls
	a.mu.Unlock()
	if again != calls {
		t.Fatalf("the engine was reloaded %d times with nothing changed", again-calls)
	}

	// The manual host is deleted: the container's route comes back.
	mu.Lock()
	delete(manual, "app.example.com")
	mu.Unlock()
	select {
	case <-a.changed:
	case <-time.After(3 * time.Second):
		t.Fatal("the deleted manual host was not noticed")
	}
	if got := a.domains(); len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("domains after the manual host went = %v", got)
	}
	cancel()
	<-done
}
