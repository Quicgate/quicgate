package docker

import (
	"fmt"
	"strings"
	"testing"
)

// testProvider builds a provider suitable for deriving without a live socket:
// settings come from the static options (setting hook is nil), access lists
// resolve from the supplied map, and selfNets fixes network-mode detection.
func testProvider(opts Options, self map[string]bool, acls map[string]int64) *Provider {
	if opts.LabelPrefix == "" {
		opts.LabelPrefix = "quicgate"
	}
	return &Provider{
		opts:     opts,
		selfNets: self,
		resolveACL: func(name string) (int64, bool) {
			id, ok := acls[name]
			return id, ok
		},
	}
}

type ctSpec struct {
	name      string
	labels    map[string]string
	exposed   []int
	published map[int]int // container port -> host port
	netMode   string
	networks  map[string]string // network name -> container IP
	running   bool
}

func makeContainer(s ctSpec) containerInspect {
	name := s.name
	if name == "" {
		name = "svc"
	}
	in := containerInspect{ID: "deadbeefcafe", Name: "/" + name}
	in.State.Running = s.running
	in.Config.Labels = s.labels
	in.Config.ExposedPorts = map[string]struct{}{}
	for _, p := range s.exposed {
		in.Config.ExposedPorts[fmt.Sprintf("%d/tcp", p)] = struct{}{}
	}
	in.HostConfig.NetworkMode = s.netMode
	in.NetworkSettings.Networks = map[string]networkEndpoint{}
	for n, ip := range s.networks {
		in.NetworkSettings.Networks[n] = networkEndpoint{IPAddress: ip}
	}
	in.NetworkSettings.Ports = map[string][]portBinding{}
	for cp, hp := range s.published {
		in.NetworkSettings.Ports[fmt.Sprintf("%d/tcp", cp)] = []portBinding{{HostIP: "0.0.0.0", HostPort: fmt.Sprint(hp)}}
	}
	return in
}

func labels(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m["quicgate."+kv[i]] = kv[i+1]
	}
	return m
}

func upstreamStr(d derived) string {
	if d.host == nil {
		return "<none>"
	}
	u := d.host.Upstream
	return fmt.Sprintf("%s://%s:%d", u.Scheme, u.Host, u.Port)
}

func TestDeriveNotEnabled(t *testing.T) {
	p := testProvider(Options{}, nil, nil)
	d := p.derive(makeContainer(ctSpec{running: true, labels: map[string]string{"other": "x"}}))
	if d.enabled {
		t.Fatal("container without quicgate.enable should not be enabled")
	}
}

func TestDeriveNotRunning(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{running: false, labels: labels("enable", "true", "host", "a.example.com")}))
	if !d.enabled || d.host != nil {
		t.Fatalf("expected enabled with no host, got host=%v", d.host)
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "not running") {
		t.Fatalf("warnings=%v", d.warnings)
	}
}

func TestDerivePublishedExplicitPort(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "grafana", running: true,
		labels:    labels("enable", "true", "host", "grafana.example.com", "port", "3000"),
		published: map[int]int{3000: 3001},
	}))
	if d.host == nil {
		t.Fatalf("expected host, warnings=%v", d.warnings)
	}
	if got := upstreamStr(d); got != "http://127.0.0.1:3001" {
		t.Fatalf("upstream=%s want http://127.0.0.1:3001", got)
	}
	if d.mode != "published" {
		t.Fatalf("mode=%s want published", d.mode)
	}
	if d.host.CertMode != "auto" || !d.host.ForceSSL {
		t.Fatalf("tls defaults: certMode=%s forceSSL=%v", d.host.CertMode, d.host.ForceSSL)
	}
}

func TestDerivePublishedAutoDetect(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com"),
		published: map[int]int{8080: 8080},
	}))
	if got := upstreamStr(d); got != "http://127.0.0.1:8080" {
		t.Fatalf("upstream=%s want http://127.0.0.1:8080 (warnings=%v)", got, d.warnings)
	}
}

func TestDeriveExcludePorts(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "exclude-ports", "9090"),
		published: map[int]int{8080: 8080, 9090: 9090},
	}))
	if got := upstreamStr(d); got != "http://127.0.0.1:8080" {
		t.Fatalf("upstream=%s want http://127.0.0.1:8080 (warnings=%v)", got, d.warnings)
	}
}

func TestDeriveAmbiguousPortsWarn(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com"),
		published: map[int]int{8080: 8080, 9090: 9090},
	}))
	if d.host != nil {
		t.Fatalf("expected no host on ambiguous ports, got %s", upstreamStr(d))
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "candidate ports") {
		t.Fatalf("warnings=%v want candidate-ports hint", d.warnings)
	}
}

func TestDerivePublishedPortNotPublished(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "port", "3000"),
		published: map[int]int{8080: 8080}, // 3000 is not published
	}))
	if d.host != nil {
		t.Fatalf("expected no host, got %s", upstreamStr(d))
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "not reachable") {
		t.Fatalf("warnings=%v want not-reachable", d.warnings)
	}
}

func TestDeriveNetworkMode(t *testing.T) {
	p := testProvider(Options{ConnectMode: "auto"}, map[string]bool{"web": true}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:   labels("enable", "true", "host", "app.example.com"),
		exposed:  []int{8080},
		netMode:  "web",
		networks: map[string]string{"web": "172.18.0.5"},
	}))
	if got := upstreamStr(d); got != "http://172.18.0.5:8080" {
		t.Fatalf("upstream=%s want http://172.18.0.5:8080 (warnings=%v)", got, d.warnings)
	}
	if d.mode != "network" {
		t.Fatalf("mode=%s want network", d.mode)
	}
}

func TestDeriveHostNetTarget(t *testing.T) {
	p := testProvider(Options{ConnectMode: "auto"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:  labels("enable", "true", "host", "app.example.com"),
		exposed: []int{9090},
		netMode: "host",
	}))
	if got := upstreamStr(d); got != "http://127.0.0.1:9090" {
		t.Fatalf("upstream=%s want http://127.0.0.1:9090 (warnings=%v)", got, d.warnings)
	}
	if d.mode != "hostnet" {
		t.Fatalf("mode=%s want hostnet", d.mode)
	}
}

func TestDeriveNetworkModeNoSharedNetworkWarns(t *testing.T) {
	p := testProvider(Options{ConnectMode: "network"}, nil, nil) // quicgate on no shared net
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:   labels("enable", "true", "host", "app.example.com"),
		exposed:  []int{8080},
		netMode:  "bridge",
		networks: map[string]string{"bridge": "172.17.0.2"},
	}))
	if d.host != nil {
		t.Fatalf("expected no host, got %s", upstreamStr(d))
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "shares no network") {
		t.Fatalf("warnings=%v want shares-no-network", d.warnings)
	}
}

func TestDeriveDefaultDomain(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published", DefaultDomain: "apps.example.com"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "grafana", running: true,
		labels:    labels("enable", "true"),
		published: map[int]int{8080: 8080},
	}))
	if d.host == nil || d.host.Domains[0] != "grafana.apps.example.com" {
		t.Fatalf("domains=%v want grafana.apps.example.com (warnings=%v)", hostDomains(d), d.warnings)
	}
}

func TestDeriveMultiDomainAndTLS(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels: labels("enable", "true", "host", "a.example.com, b.example.com",
			"scheme", "https", "tls-skip-verify", "true", "tls", "off", "port", "8080"),
		published: map[int]int{8080: 8080},
	}))
	if d.host == nil {
		t.Fatalf("expected host, warnings=%v", d.warnings)
	}
	if len(d.host.Domains) != 2 || d.host.Domains[1] != "b.example.com" {
		t.Fatalf("domains=%v", d.host.Domains)
	}
	if d.host.Upstream.Scheme != "https" || !d.host.Options.SkipTLSVerify {
		t.Fatalf("scheme=%s skipVerify=%v", d.host.Upstream.Scheme, d.host.Options.SkipTLSVerify)
	}
	if d.host.CertMode != "none" || d.host.ForceSSL {
		t.Fatalf("tls=off: certMode=%s forceSSL=%v", d.host.CertMode, d.host.ForceSSL)
	}
}

func TestDeriveAccessList(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, map[string]int64{"lan": 5})
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "access-list", "lan"),
		published: map[int]int{8080: 8080},
	}))
	if d.host == nil || d.host.AccessListID == nil || *d.host.AccessListID != 5 {
		t.Fatalf("accessListID=%v want 5 (warnings=%v)", d.host, d.warnings)
	}
}

func TestDeriveAccessListMissingWarns(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "access-list", "nope"),
		published: map[int]int{8080: 8080},
	}))
	if d.host == nil || d.host.AccessListID != nil {
		t.Fatalf("expected host with no acl, got %v", d.host)
	}
	if !hasWarning(d, "does not exist") {
		t.Fatalf("warnings=%v want does-not-exist", d.warnings)
	}
}

// The scenario the feature was extended for: one hostname with an HTTPS web
// port, an external game port exposed as a stream, and an internal port ignored.
func TestDeriveHTTPSPlusStreamsScenario(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "game", running: true,
		labels: labels("enable", "true", "host", "game.example.com", "scheme", "https",
			"port", "8443", "streams", "25565, 27015/udp", "exclude-ports", "9090"),
		published: map[int]int{8443: 8443, 25565: 25565, 27015: 27015, 9090: 9090},
	}))
	if d.host == nil || upstreamStr(d) != "https://127.0.0.1:8443" {
		t.Fatalf("host upstream=%s want https://127.0.0.1:8443 (warnings=%v)", upstreamStr(d), d.warnings)
	}
	if len(d.streams) != 2 {
		t.Fatalf("streams=%d want 2 (%v)", len(d.streams), d.streams)
	}
	s0, s1 := d.streams[0], d.streams[1]
	if s0.ListenPort != 25565 || s0.Protocol != "tcp" || s0.ForwardHost != "127.0.0.1" || s0.ForwardPort != 25565 {
		t.Fatalf("stream0=%+v", s0)
	}
	if s1.ListenPort != 27015 || s1.Protocol != "udp" || s1.ForwardPort != 27015 {
		t.Fatalf("stream1=%+v", s1)
	}
}

func TestDeriveStreamsOnly(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "ssh", running: true,
		labels:    labels("enable", "true", "streams", "2222:22/tcp"),
		published: map[int]int{22: 22},
	}))
	if d.host != nil {
		t.Fatalf("expected no host for streams-only, got %s", upstreamStr(d))
	}
	if len(d.streams) != 1 {
		t.Fatalf("streams=%v", d.streams)
	}
	if len(d.warnings) != 0 {
		t.Fatalf("streams-only should not warn, got %v", d.warnings)
	}
	s := d.streams[0]
	if s.ListenPort != 2222 || s.ForwardPort != 22 || s.ForwardHost != "127.0.0.1" {
		t.Fatalf("stream=%+v want listen 2222 -> 127.0.0.1:22", s)
	}
}

func TestDeriveStreamAccessListReused(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, map[string]int64{"lan": 7})
	d := p.derive(makeContainer(ctSpec{
		name: "db", running: true,
		labels:    labels("enable", "true", "streams", "5432", "access-list", "lan"),
		published: map[int]int{5432: 5432},
	}))
	if len(d.streams) != 1 || d.streams[0].AccessListID == nil || *d.streams[0].AccessListID != 7 {
		t.Fatalf("stream acl not reused: %+v (warnings=%v)", d.streams, d.warnings)
	}
}

func TestDeriveNothingToRouteWarns(t *testing.T) {
	p := testProvider(Options{ConnectMode: "published"}, nil, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true"), // no host, no default-domain, no streams
		published: map[int]int{8080: 8080},
	}))
	if d.host != nil || len(d.streams) != 0 {
		t.Fatal("expected nothing routed")
	}
	if !hasWarning(d, "nothing to route") {
		t.Fatalf("warnings=%v want nothing-to-route", d.warnings)
	}
}

func TestParseStreamEntry(t *testing.T) {
	cases := []struct {
		in                string
		listen, container int
		proto             string
		wantErr           bool
	}{
		{"25565", 25565, 25565, "tcp", false},
		{"2222:22", 2222, 22, "tcp", false},
		{"27015/udp", 27015, 27015, "udp", false},
		{"53:53/both", 53, 53, "both", false},
		{"nope", 0, 0, "", true},
		{"70000", 0, 0, "", true},
		{"22/xxx", 0, 0, "", true},
	}
	for _, c := range cases {
		l, cp, pr, err := parseStreamEntry(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %d:%d/%s", c.in, l, cp, pr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if l != c.listen || cp != c.container || pr != c.proto {
			t.Errorf("%q: got %d:%d/%s want %d:%d/%s", c.in, l, cp, pr, c.listen, c.container, c.proto)
		}
	}
}

func TestPortHelpers(t *testing.T) {
	if n, ok := tcpPort("8080/tcp"); !ok || n != 8080 {
		t.Fatalf("tcpPort tcp: %d %v", n, ok)
	}
	if _, ok := tcpPort("8080/udp"); ok {
		t.Fatal("tcpPort should reject udp")
	}
	if n, ok := tcpPort("443"); !ok || n != 443 {
		t.Fatalf("tcpPort bare: %d %v", n, ok)
	}
	pub := parsePublished(map[string][]portBinding{
		"3000/tcp": {{HostPort: "3001"}},
		"53/udp":   {{HostPort: "53"}},
	})
	if pub[3000] != 3001 || len(pub) != 1 {
		t.Fatalf("parsePublished=%v want {3000:3001}", pub)
	}
	ex := parseExposed(map[string]struct{}{"80/tcp": {}, "53/udp": {}})
	if len(ex) != 1 || ex[0] != 80 {
		t.Fatalf("parseExposed=%v want [80]", ex)
	}
	excl := parsePortList("80, 443 ,x, 8080")
	if !excl[80] || !excl[443] || !excl[8080] || len(excl) != 3 {
		t.Fatalf("parsePortList=%v", excl)
	}
	if !truthy("yes") || !truthy("1") || truthy("nope") {
		t.Fatal("truthy")
	}
	if !isOff("off") || !isOff("false") || isOff("on") {
		t.Fatal("isOff")
	}
}

// helpers for assertions

func hostDomains(d derived) []string {
	if d.host == nil {
		return nil
	}
	return d.host.Domains
}

func hasWarning(d derived, sub string) bool {
	for _, w := range d.warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
