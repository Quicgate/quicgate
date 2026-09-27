package docker

import (
	"fmt"
	"strings"
	"testing"
)

// testProvider builds a provider suitable for deriving without a live socket:
// settings come from the static options (setting hook is nil) and access lists
// resolve from the supplied map.
func testProvider(opts Options, acls map[string]int64) *Provider {
	if opts.LabelPrefix == "" {
		opts.LabelPrefix = "quicgate"
	}
	return &Provider{
		opts: opts,
		resolveACL: func(name string) (int64, bool) {
			id, ok := acls[name]
			return id, ok
		},
	}
}

type ctSpec struct {
	name         string
	labels       map[string]string
	exposed      []int
	published    map[int]int // container TCP port -> host port
	publishedUDP map[int]int // container UDP port -> host port
	netMode      string
	running      bool
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
	in.NetworkSettings.Ports = map[string][]portBinding{}
	for cp, hp := range s.published {
		in.NetworkSettings.Ports[fmt.Sprintf("%d/tcp", cp)] = []portBinding{{HostIP: "0.0.0.0", HostPort: fmt.Sprint(hp)}}
	}
	for cp, hp := range s.publishedUDP {
		in.NetworkSettings.Ports[fmt.Sprintf("%d/udp", cp)] = []portBinding{{HostIP: "0.0.0.0", HostPort: fmt.Sprint(hp)}}
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
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{running: true, labels: map[string]string{"other": "x"}}), "127.0.0.1")
	if d.enabled {
		t.Fatal("container without quicgate.enable should not be enabled")
	}
}

func TestDeriveNotRunning(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{running: false, labels: labels("enable", "true", "host", "a.example.com")}), "127.0.0.1")
	if !d.enabled || d.host != nil {
		t.Fatalf("expected enabled with no host, got host=%v", d.host)
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "not running") {
		t.Fatalf("warnings=%v", d.warnings)
	}
}

func TestDeriveExplicitPort(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "grafana", running: true,
		labels:    labels("enable", "true", "host", "grafana.example.com", "port", "3000"),
		published: map[int]int{3000: 3001},
	}), "127.0.0.1")
	if got := upstreamStr(d); got != "http://127.0.0.1:3001" {
		t.Fatalf("upstream=%s want http://127.0.0.1:3001 (warnings=%v)", got, d.warnings)
	}
	if d.host.CertMode != "auto" || !d.host.ForceSSL {
		t.Fatalf("tls defaults: certMode=%s forceSSL=%v", d.host.CertMode, d.host.ForceSSL)
	}
}

func TestDeriveAutoDetect(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com"),
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
	if got := upstreamStr(d); got != "http://127.0.0.1:8080" {
		t.Fatalf("upstream=%s want http://127.0.0.1:8080 (warnings=%v)", got, d.warnings)
	}
}

// A remote endpoint's address is used verbatim, which is what makes multi-host
// routing work: a container on another daemon is reached at that host's IP.
func TestDeriveRemoteAddress(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com"),
		published: map[int]int{8080: 18080},
	}), "192.168.1.9")
	if got := upstreamStr(d); got != "http://192.168.1.9:18080" {
		t.Fatalf("upstream=%s want http://192.168.1.9:18080 (warnings=%v)", got, d.warnings)
	}
}

func TestDeriveExcludePorts(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "exclude-ports", "9090"),
		published: map[int]int{8080: 8080, 9090: 9090},
	}), "127.0.0.1")
	if got := upstreamStr(d); got != "http://127.0.0.1:8080" {
		t.Fatalf("upstream=%s want http://127.0.0.1:8080 (warnings=%v)", got, d.warnings)
	}
}

func TestDeriveAmbiguousPortsWarn(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com"),
		published: map[int]int{8080: 8080, 9090: 9090},
	}), "127.0.0.1")
	if d.host != nil {
		t.Fatalf("expected no host on ambiguous ports, got %s", upstreamStr(d))
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "candidate ports") {
		t.Fatalf("warnings=%v want candidate-ports hint", d.warnings)
	}
}

func TestDerivePortNotPublished(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "port", "3000"),
		published: map[int]int{8080: 8080}, // 3000 is not published
	}), "127.0.0.1")
	if d.host != nil {
		t.Fatalf("expected no host, got %s", upstreamStr(d))
	}
	if len(d.warnings) == 0 || !strings.Contains(d.warnings[0], "not published") {
		t.Fatalf("warnings=%v want not-published", d.warnings)
	}
}

// A host-networked container binds host ports directly, so its container port
// is reachable at the host address as-is (no published mapping).
func TestDeriveHostNetTarget(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:  labels("enable", "true", "host", "app.example.com"),
		exposed: []int{9090},
		netMode: "host",
	}), "127.0.0.1")
	if got := upstreamStr(d); got != "http://127.0.0.1:9090" {
		t.Fatalf("upstream=%s want http://127.0.0.1:9090 (warnings=%v)", got, d.warnings)
	}
}

func TestDeriveDefaultDomain(t *testing.T) {
	p := testProvider(Options{DefaultDomain: "apps.example.com"}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "grafana", running: true,
		labels:    labels("enable", "true"),
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
	if d.host == nil || d.host.Domains[0] != "grafana.apps.example.com" {
		t.Fatalf("domains=%v want grafana.apps.example.com (warnings=%v)", hostDomains(d), d.warnings)
	}
}

func TestDeriveMultiDomainAndTLS(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels: labels("enable", "true", "host", "a.example.com, b.example.com",
			"scheme", "https", "tls-skip-verify", "true", "tls", "off", "port", "8080"),
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
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
	p := testProvider(Options{}, map[string]int64{"lan": 5})
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "access-list", "lan"),
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
	if d.host == nil || d.host.AccessListID == nil || *d.host.AccessListID != 5 {
		t.Fatalf("accessListID=%v want 5 (warnings=%v)", d.host, d.warnings)
	}
}

// A container that asks for an access list that does not exist must not be
// routed at all: publishing it without the restriction it asked for would make
// a label typo expose the service.
func TestDeriveAccessListMissingIsNotRouted(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "access-list", "nope", "streams", "5432"),
		published: map[int]int{8080: 8080, 5432: 5432},
	}), "127.0.0.1")
	if d.host != nil || len(d.streams) != 0 {
		t.Fatalf("container with a missing access list was routed: host=%v streams=%v", d.host, d.streams)
	}
	if !hasWarning(d, "does not exist") {
		t.Fatalf("warnings=%v want does-not-exist", d.warnings)
	}
}

// One hostname with an HTTPS web port, an external game port exposed as a
// stream, and an internal port ignored.
func TestDeriveHTTPSPlusStreamsScenario(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "game", running: true,
		labels: labels("enable", "true", "host", "game.example.com", "scheme", "https",
			"port", "8443", "streams", "25565, 27015/udp", "exclude-ports", "9090"),
		published:    map[int]int{8443: 8443, 25565: 25565, 9090: 9090},
		publishedUDP: map[int]int{27015: 27015},
	}), "127.0.0.1")
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
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "ssh", running: true,
		labels:    labels("enable", "true", "streams", "2222:22/tcp"),
		published: map[int]int{22: 22},
	}), "127.0.0.1")
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
	p := testProvider(Options{}, map[string]int64{"lan": 7})
	d := p.derive(makeContainer(ctSpec{
		name: "db", running: true,
		labels:    labels("enable", "true", "streams", "5432", "access-list", "lan"),
		published: map[int]int{5432: 5432},
	}), "127.0.0.1")
	if len(d.streams) != 1 || d.streams[0].AccessListID == nil || *d.streams[0].AccessListID != 7 {
		t.Fatalf("stream acl not reused: %+v (warnings=%v)", d.streams, d.warnings)
	}
}

func TestDeriveNothingToRouteWarns(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true"), // no host, no default-domain, no streams
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
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
	if pk, ok := parsePortKey("8080/tcp"); !ok || pk != (portKey{8080, "tcp"}) {
		t.Fatalf("parsePortKey tcp: %v %v", pk, ok)
	}
	if pk, ok := parsePortKey("8080/udp"); !ok || pk != (portKey{8080, "udp"}) {
		t.Fatalf("parsePortKey udp: %v %v", pk, ok)
	}
	if _, ok := parsePortKey("8080/sctp"); ok {
		t.Fatal("parsePortKey should reject sctp")
	}
	if pk, ok := parsePortKey("443"); !ok || pk != (portKey{443, "tcp"}) {
		t.Fatalf("parsePortKey bare: %v %v", pk, ok)
	}
	// Each protocol has its own publication (F-3: a UDP-only port used to be
	// invisible, and a both stream sent UDP to the TCP host port).
	pub := parsePublished(map[string][]portBinding{
		"3000/tcp": {{HostPort: "3001"}},
		"53/udp":   {{HostPort: "5353"}},
	})
	if pub[portKey{3000, "tcp"}] != 3001 || pub[portKey{53, "udp"}] != 5353 || len(pub) != 2 {
		t.Fatalf("parsePublished=%v want {3000/tcp:3001 53/udp:5353}", pub)
	}
	if _, ok := pub[portKey{53, "tcp"}]; ok {
		t.Fatal("a UDP publication must not count as a TCP one")
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

func TestTransportForConnect(t *testing.T) {
	ep := func(connect string) Endpoint { return Endpoint{Name: "e", Connect: connect, Address: "127.0.0.1"} }
	if base, _, err := transportFor(ep("tcp://192.168.1.9:2375")); err != nil || base != "http://192.168.1.9:2375" {
		t.Fatalf("tcp base=%s err=%v", base, err)
	}
	if base, tr, err := transportFor(ep("/var/run/docker.sock")); err != nil || base != "http://docker" || tr.DialContext == nil {
		t.Fatalf("unix base=%s dialer=%v err=%v", base, tr != nil && tr.DialContext != nil, err)
	}
	if base, _, err := transportFor(ep("unix:///var/run/docker.sock")); err != nil || base != "http://docker" {
		t.Fatalf("unix:// base=%s err=%v", base, err)
	}
	if base, tr, err := transportFor(ep("https://192.168.1.9:2376")); err != nil || base != "https://192.168.1.9:2376" || tr.TLSClientConfig == nil {
		t.Fatalf("https base=%s tls=%v err=%v", base, tr != nil && tr.TLSClientConfig != nil, err)
	}
	for _, bad := range []string{"", "192.168.1.9:2375", "tcp://192.168.1.9", "tcp://192.168.1.9:99999", "ftp://x:1", "relative/path.sock", "tcp://bad host:2375"} {
		if _, _, err := transportFor(ep(bad)); err == nil {
			t.Errorf("connect %q was accepted", bad)
		}
	}
}

// A label key quicgate does not know is a mistake, not noise: quicgate.access_list
// (wrong separator) used to publish the container with no access list at all.
// The container is not routed and the warning names the key it probably meant.
func TestDeriveUnknownLabelIsNotRouted(t *testing.T) {
	p := testProvider(Options{}, map[string]int64{"lan": 5})
	d := p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "port", "8080", "access_list", "lan", "streams", "5432"),
		published: map[int]int{8080: 8080, 5432: 5432},
	}), "127.0.0.1")
	if !d.enabled {
		t.Fatal("the container opted in; it must be listed")
	}
	if d.host != nil || len(d.streams) != 0 {
		t.Fatalf("a container with an unknown label was routed: host=%v streams=%v", d.host, d.streams)
	}
	if !hasWarning(d, "unknown label quicgate.access_list; did you mean quicgate.access-list?") {
		t.Fatalf("warnings=%v want the unknown key and the suggestion", d.warnings)
	}
	if !hasWarning(d, "not routed") {
		t.Fatalf("warnings=%v want the consequence spelled out", d.warnings)
	}

	// Other prefixes and unrelated labels are none of quicgate's business.
	d = p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels: map[string]string{"quicgate.enable": "true", "quicgate.host": "app.example.com",
			"traefik.enable": "true", "com.docker.compose.service": "app", "quicgateway": "x"},
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
	if d.host == nil {
		t.Fatalf("labels outside the prefix blocked routing: %v", d.warnings)
	}

	// A key with nothing close gets no suggestion, but is refused all the same.
	d = p.derive(makeContainer(ctSpec{
		name: "app", running: true,
		labels:    labels("enable", "true", "host", "app.example.com", "middleware.headers", "x"),
		published: map[int]int{8080: 8080},
	}), "127.0.0.1")
	if d.host != nil || !hasWarning(d, "unknown label quicgate.middleware.headers") || hasWarning(d, "did you mean") {
		t.Fatalf("host=%v warnings=%v", d.host, d.warnings)
	}
	for in, want := range map[string]string{"access_list": "access-list", "hosts": "host", "Port": "port", "exclude_ports": "exclude-ports", "tls-skip": "", "nonsense": ""} {
		if got := suggestLabel(in); got != want {
			t.Errorf("suggestLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// quicgate.streams resolves each protocol's own publication: a 53/udp stream
// follows the container's UDP mapping (it used to read TCP mappings only and
// warn "not published"), and a both stream needs the two protocols on one host
// port, because it forwards both to one port.
func TestDeriveStreamsResolveUDPAndBoth(t *testing.T) {
	p := testProvider(Options{}, nil)
	d := p.derive(makeContainer(ctSpec{
		name: "dns", running: true,
		labels:       labels("enable", "true", "streams", "5353:53/udp, 2222:22/both, 8000:80/tcp"),
		published:    map[int]int{22: 19332, 80: 19330},
		publishedUDP: map[int]int{53: 19331, 22: 19332},
	}), "127.0.0.1")
	if len(d.warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", d.warnings)
	}
	if len(d.streams) != 3 {
		t.Fatalf("streams=%d want 3: %+v", len(d.streams), d.streams)
	}
	udp, both, tcp := d.streams[0], d.streams[1], d.streams[2]
	if udp.Protocol != "udp" || udp.ListenPort != 5353 || udp.ForwardPort != 19331 {
		t.Fatalf("udp stream=%+v want 5353/udp -> 19331 (the UDP publication)", udp)
	}
	if both.Protocol != "both" || both.ListenPort != 2222 || both.ForwardPort != 19332 {
		t.Fatalf("both stream=%+v want 2222/both -> 19332", both)
	}
	if tcp.Protocol != "tcp" || tcp.ForwardPort != 19330 {
		t.Fatalf("tcp stream=%+v", tcp)
	}

	// UDP asked for, only TCP published: not routed, and the warning names
	// the protocol, so the fix is obvious.
	d = p.derive(makeContainer(ctSpec{
		name: "dns", running: true,
		labels:    labels("enable", "true", "streams", "53/udp"),
		published: map[int]int{53: 53},
	}), "127.0.0.1")
	if len(d.streams) != 0 || !hasWarning(d, "53/udp is not published") {
		t.Fatalf("streams=%v warnings=%v", d.streams, d.warnings)
	}

	// A both stream whose protocols are published on different host ports
	// cannot be one stream: refused with the two ports, never UDP to the TCP port.
	d = p.derive(makeContainer(ctSpec{
		name: "game", running: true,
		labels:       labels("enable", "true", "streams", "27015/both"),
		published:    map[int]int{27015: 27015},
		publishedUDP: map[int]int{27015: 27016},
	}), "127.0.0.1")
	if len(d.streams) != 0 || !hasWarning(d, "27015 for tcp and 27016 for udp") {
		t.Fatalf("streams=%v warnings=%v", d.streams, d.warnings)
	}
	// One protocol of a both stream missing names that protocol.
	d = p.derive(makeContainer(ctSpec{
		name: "game", running: true,
		labels:    labels("enable", "true", "streams", "27015/both"),
		published: map[int]int{27015: 27015},
	}), "127.0.0.1")
	if len(d.streams) != 0 || !hasWarning(d, "27015/udp is not published") {
		t.Fatalf("streams=%v warnings=%v", d.streams, d.warnings)
	}

	// A host-networked container binds its ports directly, on either protocol.
	d = p.derive(makeContainer(ctSpec{
		name: "dns", running: true,
		labels:  labels("enable", "true", "streams", "53/both"),
		netMode: "host",
	}), "192.168.1.9")
	if len(d.streams) != 1 || d.streams[0].Protocol != "both" || d.streams[0].ForwardPort != 53 || d.streams[0].ForwardHost != "192.168.1.9" {
		t.Fatalf("host-network both stream=%+v warnings=%v", d.streams, d.warnings)
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
