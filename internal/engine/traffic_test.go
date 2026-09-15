package engine

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"quicgate/internal/store"
)

// hourBoundary is a unix time on an hour boundary, so a test's samples line up
// with every resolution of the history.
var hourBoundary = time.Unix(1_800_000_000, 0)

func newTestTraffic(t *testing.T, dataDir string) (*trafficStats, *accessLogger) {
	t.Helper()
	l := newAccessLogger(t.TempDir())
	t.Cleanup(func() { _ = l.Close() })
	return newTrafficStats(l, nil, nil, nil, dataDir), l
}

// at is a regular sample's arguments: the counters are read at the interval end.
func at(end time.Time) (time.Time, time.Time) { return end, end }

func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// The HTTP listeners count what their client sockets carry: request and
// response bodies plus headers, and every connection while it is open.
func TestCountedListenerCountsWireBytes(t *testing.T) {
	e, _ := newTestEngine(t)
	ln, err := e.listenCounted("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := e.traffic.port("tcp:0") // named after the configured port, which is 0 here
	body := bytes.Repeat([]byte("r"), 50_000)
	reply := bytes.Repeat([]byte("s"), 80_000)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(reply)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	resp, err := client.Post("http://"+ln.Addr().String()+"/", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(got) != len(reply) {
		t.Fatalf("read %d bytes of the reply, want %d", len(got), len(reply))
	}
	waitUntil(t, func() bool { return p.active.Load() == 0 }, "the closed connection to leave the open count")
	if in := p.in.Load(); in <= uint64(len(body)) {
		t.Fatalf("received %d bytes, want more than the %d-byte body (headers count too)", in, len(body))
	}
	if out := p.out.Load(); out <= uint64(len(reply)) {
		t.Fatalf("sent %d bytes, want more than the %d-byte reply", out, len(reply))
	}
	if n := p.accepted.Load(); n != 1 {
		t.Fatalf("accepted %d connections, want 1", n)
	}
}

// Every quicgate control that turns a request away says why, and the report
// and the metrics count it under that reason. Refusals by the upstream do not
// count.
func TestRefusedRequestsAreCountedByReason(t *testing.T) {
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upstream-forbids" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	auth := backend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Uri") == "/login-first" {
			http.Redirect(w, r, "https://sso.test/login", http.StatusFound)
			return
		}
		http.Error(w, "denied", http.StatusUnauthorized)
	})
	lan := mustCreateACL(t, st, &store.AccessList{Name: "lan", Satisfy: "all",
		Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"open.test"}, Upstream: up})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"acl.test"}, Upstream: up, AccessListID: &lan})
	exploit := &store.Host{Type: "proxy", Domains: []string{"exploit.test"}, Upstream: up}
	exploit.Options.BlockExploits = true
	mustCreateHost(t, st, exploit)
	bots := &store.Host{Type: "proxy", Domains: []string{"bots.test"}, Upstream: up}
	bots.Options.BlockBadBots = true
	mustCreateHost(t, st, bots)
	limited := &store.Host{Type: "proxy", Domains: []string{"limited.test"}, Upstream: up}
	limited.Options.RateLimit = &store.RateLimit{RPS: 0.001, Burst: 1}
	mustCreateHost(t, st, limited)
	fwd := &store.Host{Type: "proxy", Domains: []string{"fwd.test"}, Upstream: up}
	fwd.Options.ForwardAuth = &store.ForwardAuth{URL: fmt.Sprintf("%s://%s:%d/verify", auth.Scheme, auth.Host, auth.Port)}
	mustCreateHost(t, st, fwd)
	reload(t, e)
	// The store refuses dangling references, so these arrive the way a Docker
	// label can bring them: a path rule naming a missing list, and SSO naming a
	// missing provider. Both fail closed.
	missing := int64(999)
	closed := store.Host{Type: "proxy", Domains: []string{"closed.test"}, Upstream: up, CertMode: "none", Enabled: true}
	closed.Options.AuthRules = []store.AuthRule{
		{Path: "/admin/", Mode: "accessList", AccessListID: &missing},
		{Path: "/sso/", Mode: "oidc"},
		{Path: "/fwd/", Mode: "forwardAuth"},
	}
	sso := store.Host{Type: "proxy", Domains: []string{"sso.test"}, Upstream: up, CertMode: "none", Enabled: true}
	sso.Options.OIDC = &store.OIDCAuth{ProviderID: missing}
	e.SetDockerRoutes([]store.Host{closed, sso}, nil)
	vault := mustCreateACL(t, st, &store.AccessList{Name: "vault", Satisfy: "all", Users: []store.AccessUser{{Username: "family", Password: "right"}}})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"vault.test"}, Upstream: up, AccessListID: &vault})
	reload(t, e)

	serve := e.ban.wrap(e.accessLog.wrap(e.serveHTTPS))
	do := func(method, host, path, ip string, hdr map[string]string) int {
		r := httptest.NewRequest(method, "http://"+host+path, nil)
		r.Host = host
		r.RemoteAddr = ip + ":40000"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		serve(rr, r)
		return rr.Code
	}
	for _, c := range []struct {
		method, host, path string
		hdr                map[string]string
		want               int
	}{
		{"GET", "open.test", "/", nil, http.StatusOK},
		{"GET", "open.test", "/upstream-forbids", nil, http.StatusForbidden},
		{"GET", "acl.test", "/", nil, http.StatusForbidden},
		{"OPTIONS", "acl.test", "/", map[string]string{"Origin": "https://app.test", "Access-Control-Request-Method": "POST"}, http.StatusForbidden},
		{"GET", "closed.test", "/admin/users", nil, http.StatusForbidden},
		{"GET", "closed.test", "/sso/home", nil, http.StatusForbidden},
		{"GET", "closed.test", "/fwd/home", nil, http.StatusForbidden},
		{"GET", "sso.test", "/", nil, http.StatusForbidden},
		// The login prompt a client without credentials gets is not a refusal;
		// wrong credentials are.
		{"GET", "vault.test", "/", nil, http.StatusUnauthorized},
		{"GET", "vault.test", "/", map[string]string{"Authorization": basic("family", "wrong")}, http.StatusUnauthorized},
		{"GET", "vault.test", "/", map[string]string{"Authorization": basic("family", "right")}, http.StatusOK},
		{"GET", "exploit.test", "/?q=union%20select%201", nil, http.StatusForbidden},
		{"GET", "open.test", "/a/../b", nil, http.StatusBadRequest},
		{"GET", "bots.test", "/", map[string]string{"User-Agent": "sqlmap/1.7"}, http.StatusForbidden},
		{"GET", "limited.test", "/", nil, http.StatusOK},
		{"GET", "limited.test", "/", nil, http.StatusTooManyRequests},
		{"GET", "fwd.test", "/", nil, http.StatusUnauthorized},
		{"GET", "fwd.test", "/login-first", nil, http.StatusFound},
	} {
		if got := do(c.method, c.host, c.path, "127.0.0.1", c.hdr); got != c.want {
			t.Fatalf("%s %s%s: status %d, want %d", c.method, c.host, c.path, got, c.want)
		}
	}
	// A banned client is turned away before the access log sees it.
	e.banCfg.Store(&banConfig{enabled: true, threshold: 1, window: time.Minute, banFor: time.Hour})
	e.ban.recordFailure("192.0.2.9:1", "test.host", "test")
	if got := do("GET", "open.test", "/", "192.0.2.9", nil); got != http.StatusForbidden {
		t.Fatalf("banned client: status %d, want 403", got)
	}

	now := time.Now()
	e.traffic.sample(at(now.Truncate(sampleStep * time.Second)))
	rep, err := e.traffic.report("1h", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"accessList": 4, "sso": 2, "exploit": 2, "bot": 1, "rateLimit": 1, "forwardAuth": 2, "banned": 1}
	for i := blockNone + 1; i < numBlockReasons; i++ {
		name := blockReasonNames[i]
		if got := rep.Totals.Blocked[name]; got != want[name] {
			t.Errorf("blocked %s = %d, want %d (all: %v)", name, got, want[name], rep.Totals.Blocked)
		}
	}
	if rep.Totals.Requests != 18 {
		t.Errorf("requests = %d, want 18 (the banned one never reaches the log)", rep.Totals.Requests)
	}
	if rep.Banned != 1 {
		t.Errorf("banned now = %d, want 1", rep.Banned)
	}
	metrics := e.MetricsText()
	for _, line := range []string{`quicgate_blocked_total{reason="exploit"} 2`, `quicgate_blocked_total{reason="banned"} 1`, `quicgate_requests_by_protocol_total{protocol="HTTP/1.1"} 18`} {
		if !strings.Contains(metrics, line) {
			t.Errorf("metrics lack %q", line)
		}
	}
}

// A request refused for a missing client certificate counts as such.
func TestClientCertificateRefusalIsCounted(t *testing.T) {
	f := newMTLSFixture(t, "require")
	r := httptest.NewRequest(http.MethodGet, "https://secure.test/", nil)
	r.Host = "secure.test"
	r.RemoteAddr = "127.0.0.1:40000"
	r.TLS = &tls.ConnectionState{ServerName: "secure.test"}
	rr := httptest.NewRecorder()
	f.e.accessLog.wrap(f.e.serveHTTPS)(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rr.Code)
	}
	if n := f.e.accessLog.blocked[blockClientCert].Load(); n != 1 {
		t.Fatalf("client certificate refusals = %d, want 1", n)
	}
}

// Frames roll up from 10 seconds to 5 minutes to an hour, and every range
// reports the same totals, with the frame still filling as its last point.
func TestTrafficHistoryRollsUpAcrossResolutions(t *testing.T) {
	ts, l := newTestTraffic(t, "")
	port := ts.port("tcp:443")
	// 35 samples from an hour boundary: 30 complete the first 5-minute frame,
	// 5 start the next.
	for i := 1; i <= 35; i++ {
		l.total.Add(2)
		l.status2xx.Add(2)
		port.in.Add(100)
		port.out.Add(1000)
		ts.sample(at(hourBoundary.Add(time.Duration(i*sampleStep) * time.Second)))
	}
	now := hourBoundary.Add(353 * time.Second)
	ports := func() []PortTraffic { return []PortTraffic{{Key: "tcp:443"}} }

	hour, err := ts.report("1h", now, ports())
	if err != nil {
		t.Fatal(err)
	}
	if hour.Step != 10 || len(hour.Series.In) != 360 || hour.Start != hourBoundary.Unix()+350-3600 || hour.LastSpan != 10 {
		t.Fatalf("1h: step %d, %d points, start %d, last span %d", hour.Step, len(hour.Series.In), hour.Start, hour.LastSpan)
	}
	for i, v := range hour.Series.In {
		if hasData := i >= 360-35; (hasData && v != 100) || (!hasData && v != -1) {
			t.Fatalf("1h point %d = %v, want %v", i, v, map[bool]float64{true: 100, false: -1}[hasData])
		}
	}

	day, err := ts.report("24h", now, ports())
	if err != nil {
		t.Fatal(err)
	}
	n := len(day.Series.In)
	if day.Step != 300 || n != 288 || day.Series.In[n-3] != -1 || day.Series.In[n-2] != 3000 || day.Series.In[n-1] != 500 || day.LastSpan != 50 {
		t.Fatalf("24h: step %d, %d points, last three %v, last span %d", day.Step, n, day.Series.In[n-3:], day.LastSpan)
	}

	week, err := ts.report("7d", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	n = len(week.Series.In)
	if week.Step != 3600 || n != 168 || week.Series.In[n-2] != -1 || week.Series.In[n-1] != 3500 || week.LastSpan != 350 {
		t.Fatalf("7d: step %d, %d points, last two %v, last span %d", week.Step, n, week.Series.In[n-2:], week.LastSpan)
	}

	six, err := ts.report("6h", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []TrafficReport{hour, six, day, week} {
		if r.Totals.In != 3500 || r.Totals.Out != 35000 || r.Totals.Requests != 70 || r.Totals.Status["2xx"] != 70 {
			t.Fatalf("%s totals: in %d, out %d, requests %d, 2xx %d; want 3500, 35000, 70, 70", r.Range, r.Totals.In, r.Totals.Out, r.Totals.Requests, r.Totals.Status["2xx"])
		}
	}
	// Sparklines are rates, so a steady 1100 bytes per 10 seconds reads 110
	// per second at every resolution, the partly filled last interval included.
	for _, c := range []struct {
		r         TrafficReport
		firstData int // the 35 samples cover 6 of the hour's 60 sparkline points, and 1 of the day's 48
	}{{hour, 54}, {day, 47}} {
		if c.r.Ports[0].In != 3500 {
			t.Fatalf("%s port row: in %d, want 3500", c.r.Range, c.r.Ports[0].In)
		}
		for i, v := range c.r.Ports[0].Spark {
			if want := map[bool]float64{true: 110, false: -1}[i >= c.firstData]; v != want {
				t.Fatalf("%s sparkline point %d = %v, want %v", c.r.Range, i, v, want)
			}
		}
	}
	if _, err := ts.report("1y", now, nil); err == nil {
		t.Fatal("an unknown range was accepted")
	}
}

// Time quicgate was not running shows as gaps, not as zero traffic.
func TestTrafficReportShowsDowntimeAsGaps(t *testing.T) {
	ts, _ := newTestTraffic(t, "")
	port := ts.port("tcp:80")
	for _, i := range []int{1, 2, 3, 7, 8} {
		port.out.Add(10)
		ts.sample(at(hourBoundary.Add(time.Duration(i*sampleStep) * time.Second)))
	}
	rep, err := ts.report("1h", hourBoundary.Add(80*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Series.Out[len(rep.Series.Out)-8:]
	want := gapSeries{10, 10, 10, -1, -1, -1, 10, 10}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("last 8 points %v, want %v", got, want)
	}
}

func TestTrafficLatencyPercentiles(t *testing.T) {
	var b [numLatencyBuckets]uint64
	if p := percentile(&b, .5); p != -1 {
		t.Fatalf("no samples: p50 = %v, want -1", p)
	}
	b[latencyBucket(3*time.Millisecond)] = 50
	b[latencyBucket(80*time.Millisecond)] = 50
	if p := percentile(&b, .5); p != 5 {
		t.Fatalf("p50 = %v, want 5", p)
	}
	if p := percentile(&b, .95); p != 95 {
		t.Fatalf("p95 = %v, want 95", p)
	}
	b[numLatencyBuckets-1] = 900
	if p := percentile(&b, .99); p != 10000 {
		t.Fatalf("p99 with slow responses = %v, want 10000", p)
	}
	for d, want := range map[time.Duration]int{5 * time.Millisecond: 0, 5*time.Millisecond + 1: 1, time.Minute: len(latencyBounds)} {
		if got := latencyBucket(d); got != want {
			t.Fatalf("latencyBucket(%v) = %d, want %d", d, got, want)
		}
	}
}

// A 103 Early Hints response comes before the real one: it is neither the
// status nor the time to first byte.
func TestInformationalResponseIsNotTheStatus(t *testing.T) {
	l := newAccessLogger(t.TempDir())
	t.Cleanup(func() { _ = l.Close() })
	srv := httptest.NewServer(l.wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</app.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	waitUntil(t, func() bool { return l.total.Load() == 1 }, "the request to be logged")
	if n := l.status2xx.Load(); n != 1 {
		t.Fatalf("2xx responses = %d, want 1", n)
	}
	var timed uint64
	for i := range l.latency {
		timed += l.latency[i].Load()
	}
	if timed != 1 {
		t.Fatalf("%d responses timed, want 1", timed)
	}
	for i := 0; i <= latencyBucket(25*time.Millisecond); i++ {
		if n := l.latency[i].Load(); n != 0 {
			t.Fatalf("time to first byte landed in bucket %d (up to %v ms), before the final response was written", i, latencyBounds[i])
		}
	}
}

// The history is saved and restored, so a restart keeps the charts; a damaged
// file is ignored.
func TestTrafficHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first, l := newTestTraffic(t, dir)
	hc := &hostCounters{}
	hc.total.Add(7)
	hc.bytes.Add(700)
	l.perHost.Store("app.example", hc)
	first.port("udp:443").out.Add(4096)
	first.sample(at(hourBoundary.Add(sampleStep * time.Second)))
	if err := first.save(); err != nil {
		t.Fatal(err)
	}

	second, _ := newTestTraffic(t, dir)
	rep, err := second.report("1h", hourBoundary.Add(12*time.Second), []PortTraffic{{Key: "udp:443"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals.Out != 4096 || rep.Ports[0].Out != 4096 || len(rep.Hosts) != 1 || rep.Hosts[0].Name != "app.example" || rep.Hosts[0].Requests != 7 {
		t.Fatalf("after a restart: out %d, port out %d, hosts %+v", rep.Totals.Out, rep.Ports[0].Out, rep.Hosts)
	}

	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), []byte("{damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, _ := newTestTraffic(t, dir)
	rep, err = third.report("1h", hourBoundary.Add(12*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals.Out != 0 {
		t.Fatalf("a damaged history file was used: out %d", rep.Totals.Out)
	}

	// A frame naming a dimension the file does not define is dropped.
	bad := `{"version":1,"dims":["port:tcp:1"],"levels":[{"frames":[{"t":1800000000,"out":5,"d":[{"i":7,"out":5}]}]},{},{}],"lastSample":1800000010}`
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	fourth, _ := newTestTraffic(t, dir)
	rep, err = fourth.report("1h", hourBoundary.Add(12*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals.Out != 0 {
		t.Fatalf("a frame with an undefined dimension was loaded: out %d", rep.Totals.Out)
	}
}

// TCP and UDP streams count the bytes their clients send and receive, their
// connections, and the clients a source filter refuses.
func TestStreamTrafficIsCounted(t *testing.T) {
	ts, _ := newTestTraffic(t, "")
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP loopback: %v", err)
	}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()

	tcpPort, udpPort, filteredPort, filteredUDPPort := freeTCPPort(t), freeUDPPort(t), freeTCPPort(t), freeUDPPort(t)
	sm := NewStreamManager()
	sm.traffic = ts
	t.Cleanup(sm.StopAll)
	sm.Sync([]store.Stream{
		{ID: 1, ListenPort: tcpPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: echo.Addr().(*net.TCPAddr).Port, Enabled: true},
		{ID: 2, ListenPort: udpPort, Protocol: "udp", ForwardHost: "127.0.0.1", ForwardPort: udpEcho.LocalAddr().(*net.UDPAddr).Port, Enabled: true},
		{ID: 3, ListenPort: filteredPort, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 9, AllowedCIDRs: []string{"10.0.0.0/8"}, Enabled: true},
		{ID: 4, ListenPort: filteredUDPPort, Protocol: "udp", ForwardHost: "127.0.0.1", ForwardPort: 9, AllowedCIDRs: []string{"10.0.0.0/8"}, Enabled: true},
	}, nil, nil)

	payload := bytes.Repeat([]byte("x"), 10_000)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	tcp := ts.port(fmt.Sprintf("tcp:%d", tcpPort))
	waitUntil(t, func() bool { return tcp.active.Load() == 0 && tcp.out.Load() == 10_000 }, "the TCP stream connection to finish")
	if in, n := tcp.in.Load(), tcp.accepted.Load(); in != 10_000 || n != 1 {
		t.Fatalf("TCP stream: received %d bytes over %d connections, want 10000 over 1", in, n)
	}

	u, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.Write(payload[:1200]); err != nil {
		t.Fatal(err)
	}
	if n, err := u.Read(make([]byte, 2000)); err != nil || n != 1200 {
		t.Fatalf("UDP echo: %d bytes, %v", n, err)
	}
	udp := ts.port(fmt.Sprintf("udp:%d", udpPort))
	waitUntil(t, func() bool { return udp.out.Load() == 1200 }, "the UDP reply to be counted")
	if in, n, open := udp.in.Load(), udp.accepted.Load(), udp.active.Load(); in != 1200 || n != 1 || open != 1 {
		t.Fatalf("UDP stream: received %d bytes, %d sessions, %d open; want 1200, 1, 1", in, n, open)
	}

	refused, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", filteredPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = refused.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(refused)
	_ = refused.Close()
	waitUntil(t, func() bool { return sm.refused.Load() == 1 }, "the filtered TCP client to be counted as refused")
	ru, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", filteredUDPPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ru.Close()
	waitUntil(t, func() bool { _, _ = ru.Write([]byte("hi")); return sm.refused.Load() >= 2 }, "the filtered UDP packet to be counted as refused")
	// A refused sender counts once, however many packets it sends.
	filtered := ts.port(fmt.Sprintf("udp:%d", filteredUDPPort))
	before := filtered.in.Load()
	for i := 0; i < 5; i++ {
		_, _ = ru.Write([]byte("hi"))
	}
	waitUntil(t, func() bool { return filtered.in.Load() >= before+10 }, "the later packets to arrive")
	if n := sm.refused.Load(); n != 2 {
		t.Fatalf("refusals = %d after more packets from the same refused sender, want 2", n)
	}

	// Stopping the listeners closes their sessions.
	sm.StopAll()
	if open := udp.active.Load(); open != 0 {
		t.Fatalf("%d UDP sessions still open after the listeners stopped", open)
	}
}

// HTTP/3 connections are counted from quic-go's own byte counts, and forgotten
// once closed.
func TestHTTP3TrafficIsCounted(t *testing.T) {
	e, _ := newTestEngine(t)
	e.cfg.HTTPSAddr = ":443"
	ts := e.traffic
	ca := newTestCA(t, "h3-ca")
	cert := ca.issue(t, "h3.test", []string{"h3.test"}, x509.ExtKeyUsageServerAuth)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP loopback: %v", err)
	}
	reply := bytes.Repeat([]byte("h"), 30_000)
	srv := e.newHTTP3Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(reply)
	}), &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "h3.test"}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Post("https://"+pc.LocalAddr().String()+"/", "text/plain", bytes.NewReader(bytes.Repeat([]byte("q"), 20_000)))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 3 || len(got) != len(reply) {
		t.Fatalf("test setup: HTTP/%d, %d bytes", resp.ProtoMajor, len(got))
	}

	p := ts.port("udp:443")
	ts.quic.drain()
	if in, out, n, open := p.in.Load(), p.out.Load(), p.accepted.Load(), p.active.Load(); in < 20_000 || out < 30_000 || n != 1 || open != 1 {
		t.Fatalf("HTTP/3: received %d, sent %d, %d connections, %d open; want at least 20000 and 30000, 1, 1", in, out, n, open)
	}
	if rep, err := ts.report("1h", time.Now(), nil); err != nil || rep.Open != 1 {
		t.Fatalf("report: %d connections open now (%v), want 1", rep.Open, err)
	}
	_ = tr.Close()
	waitUntil(t, func() bool { ts.quic.drain(); return p.active.Load() == 0 }, "the closed HTTP/3 connection to be forgotten")
}

func TestTrafficCountriesAreClassifiedAndBounded(t *testing.T) {
	lookup := func(ip net.IP) string {
		if ip.Equal(net.ParseIP("193.0.6.139")) {
			return "NL"
		}
		return ""
	}
	for ip, want := range map[string]string{"193.0.6.139": "NL", "192.168.1.20": "LAN", "10.1.2.3": "LAN", "127.0.0.1": "LAN",
		"fe80::1": "LAN", "fd00::5": "LAN", "8.8.8.8": "unknown", "not-an-ip": "unknown"} {
		if got := clientCountry(ip, lookup); got != want {
			t.Errorf("clientCountry(%s) = %q, want %q", ip, got, want)
		}
	}

	ts, _ := newTestTraffic(t, "")
	ts.countClient("193.0.6.139")
	if len(ts.countries) != 0 {
		t.Fatalf("counted countries without a GeoIP database: %v", ts.countries)
	}

	// The access log hands every logged client address to the counter, off
	// the request path, and the engine connects the two.
	l := newAccessLogger(t.TempDir())
	seen := make(chan string, 1)
	l.client = func(ip string) { seen <- ip }
	l.wrap(func(w http.ResponseWriter, r *http.Request) {})(httptest.NewRecorder(), &http.Request{Method: "GET", Host: "a.test", RemoteAddr: "198.51.100.7:5000", URL: &url.URL{Path: "/"}, Header: http.Header{}, ProtoMajor: 1})
	select {
	case ip := <-seen:
		if ip != "198.51.100.7" {
			t.Fatalf("client hook got %q, want 198.51.100.7", ip)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client hook was not called")
	}
	_ = l.Close()
	if e, _ := newTestEngine(t); e.accessLog.client == nil {
		t.Fatal("the engine does not count clients by country")
	}
	for i := 0; i < 2*maxCountries; i++ {
		ts.countCountry(fmt.Sprintf("C%d", i))
	}
	ts.countCountry("C0")
	if len(ts.countries) != maxCountries || ts.countries["C0"] != 2 {
		t.Fatalf("%d countries tracked (C0 = %d), want %d (C0 = 2)", len(ts.countries), ts.countries["C0"], maxCountries)
	}
}

// The dimension table has a hard size. New dimensions that do not fit are left
// out rather than attributed to someone else, and entries no frame uses are
// dropped and the rest renumbered.
func TestTrafficDimensionTableStaysBounded(t *testing.T) {
	defer func(n int) { maxTrafficDims = n }(maxTrafficDims)
	maxTrafficDims = 4
	ts, l := newTestTraffic(t, "")
	host := func(name string, n uint64) {
		hc := &hostCounters{}
		hc.total.Add(n)
		l.perHost.Store(name, hc)
	}
	host("a.test", 1)
	host("b.test", 2)
	ts.sample(at(hourBoundary.Add(10 * time.Second)))
	host("c.test", 3)
	host("d.test", 4)
	host("e.test", 5)
	ts.sample(at(hourBoundary.Add(20 * time.Second)))
	rep, err := ts.report("1h", hourBoundary.Add(20*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]uint64{}
	for _, h := range rep.Hosts {
		got[h.Name] = h.Requests
	}
	if want := map[string]uint64{"a.test": 1, "b.test": 2, "c.test": 3, "d.test": 4}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts %v, want %v", got, want)
	}

	ts2, _ := newTestTraffic(t, "")
	ts2.dims = []string{"host:gone.test", "host:kept.test", "host:kept.test", "port:tcp:443"}
	ts2.levels[0].Frames = []frame{{Start: 10, Dims: []dimFrame{{ID: 1, Count: 2}, {ID: 2, Count: 3}, {ID: 3, In: 9}}}}
	ts2.compactDims()
	if want := []string{"host:kept.test", "port:tcp:443"}; !reflect.DeepEqual(ts2.dims, want) {
		t.Fatalf("dims %v, want %v", ts2.dims, want)
	}
	if want := []dimFrame{{ID: 0, Count: 5}, {ID: 1, In: 9}}; !reflect.DeepEqual(ts2.levels[0].Frames[0].Dims, want) {
		t.Fatalf("frame dims %+v, want %+v", ts2.levels[0].Frames[0].Dims, want)
	}
}

// The port table lists the engine's own listeners and every stream, with its
// state and whether UPnP mapped it on the router.
func TestTrafficPortTableDescribesListeners(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "quicgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := New(Config{HTTPAddr: ":18080", HTTPSAddr: ":18443", DataDir: dir}, st)
	t.Cleanup(func() { _ = e.accessLog.Close() })
	e.upnp = &UPnPManager{mapped: map[string]bool{"TCP:18443": true}}
	e.upnp.publish()

	// Wildcard: a loopback-only socket does not block a wildcard bind on Windows.
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	free := freeTCPPort(t)
	t.Cleanup(e.streams.StopAll)
	e.streams.Sync([]store.Stream{
		{ID: 4, ListenPort: free, Protocol: "tcp", ForwardHost: "192.0.2.10", ForwardPort: 25, Enabled: true},
		{ID: 5, ListenPort: busyPort, Protocol: "tcp", ForwardHost: "192.0.2.11", ForwardPort: 22, Enabled: true},
	}, nil, nil)

	rep, err := e.TrafficReport("1h")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]PortTraffic{}
	for _, p := range rep.Ports {
		byKey[p.Key] = p
	}
	check := func(key, service, state string, exposed bool) {
		t.Helper()
		p, ok := byKey[key]
		if !ok {
			t.Fatalf("no row for %s in %+v", key, rep.Ports)
		}
		if p.Service != service || p.State != state || p.Exposed == nil || *p.Exposed != exposed || len(p.Spark) != 60 {
			t.Fatalf("%s: %+v", key, p)
		}
	}
	check("tcp:18080", "HTTP", "listening", false)
	check("tcp:18443", "HTTPS", "listening", true)
	check("udp:18443", "HTTP/3", "listening", false)
	check(fmt.Sprintf("tcp:%d", free), "TCP stream", "listening", false)
	check(fmt.Sprintf("tcp:%d", busyPort), "TCP stream", "failed", false)
	if p := byKey[fmt.Sprintf("tcp:%d", free)]; p.Detail != "to 192.0.2.10:25" || p.StreamID != 4 {
		t.Fatalf("stream row: %+v", p)
	}
}

// A counted connection half-closes like the socket it wraps. net/http relies on
// that to deliver a response before closing a connection whose request body it
// did not read.
func TestCountedConnHalfCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := countedListener{Listener: ln, c: &portCounters{}}
	defer cl.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := cl.Accept(); err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	cw, ok := server.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("a counted connection cannot half-close")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("client read after the half-close: %d bytes, %v; want EOF", n, err)
	}
	if _, err := client.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 10)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "still here" {
		t.Fatalf("server read after its half-close: %q, %v", buf, err)
	}
}

// freeTCPRange finds n consecutive ports free on every interface.
func freeTCPRange(t *testing.T, n int) int {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		first := 20000 + int(time.Now().UnixNano()%20000)
		ok := true
		var held []net.Listener
		for p := first; p < first+n; p++ {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
			if err != nil {
				ok = false
				break
			}
			held = append(held, ln)
		}
		for _, ln := range held {
			_ = ln.Close()
		}
		if ok {
			return first
		}
	}
	t.Fatal("no free port range")
	return 0
}

// Moving a range's first port restarts the ports whose target and traffic
// counters depend on it, instead of leaving them on the old offsets.
func TestRangeStreamEditRestartsShiftedPorts(t *testing.T) {
	base := freeTCPRange(t, 3)
	sm := NewStreamManager()
	t.Cleanup(sm.StopAll)
	stream := func(from int) []store.Stream {
		return []store.Stream{{ID: 1, ListenPort: from, ListenPortEnd: base + 2, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 7000, Enabled: true}}
	}
	key := fmt.Sprintf("tcp:%d", base+1)
	target := func() string {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		if f := sm.active[key]; f != nil {
			return f.target
		}
		return ""
	}
	sm.Sync(stream(base), nil, nil)
	if got := target(); got != "127.0.0.1:7001" {
		t.Fatalf("port %d forwards to %q, want 127.0.0.1:7001", base+1, got)
	}
	sm.Sync(stream(base+1), nil, nil)
	if got := target(); got != "127.0.0.1:7000" {
		t.Fatalf("after moving the range start, port %d forwards to %q, want 127.0.0.1:7000", base+1, got)
	}
}

// Rates divide by the seconds of traffic a point holds, so a point quicgate
// was only partly running in, or the partial interval saved at shutdown and
// continued after a restart, does not read as a drop.
func TestTrafficRatesUseCoveredSeconds(t *testing.T) {
	dir := t.TempDir()
	first, _ := newTestTraffic(t, dir)
	port := first.port("tcp:443")
	first.lastRead = hourBoundary.Add(6 * time.Second) // started 4 seconds before the first boundary
	port.out.Add(400)
	first.sample(at(hourBoundary.Add(10 * time.Second)))
	port.out.Add(1000)
	first.sample(at(hourBoundary.Add(20 * time.Second)))
	port.out.Add(300)
	if err := first.finish(hourBoundary.Add(23 * time.Second)); err != nil { // stopped 3 seconds into the next one
		t.Fatal(err)
	}
	rep, err := first.report("1h", hourBoundary.Add(31*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	n := len(rep.Series.Out)
	if got, want := rep.Series.Secs[n-3:], (gapSeries{4, 10, 3}); !reflect.DeepEqual(got, want) {
		t.Fatalf("seconds per point %v, want %v", got, want)
	}

	// Restarted 2 seconds later, in the same interval: the new frame joins the
	// partial one.
	second, _ := newTestTraffic(t, dir)
	second.lastRead = hourBoundary.Add(25 * time.Second)
	second.port("tcp:443").out.Add(700)
	second.sample(at(hourBoundary.Add(30 * time.Second)))
	rep, err = second.report("1h", hourBoundary.Add(31*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	n = len(rep.Series.Out)
	if rep.Series.Secs[n-1] != 8 || rep.Series.Out[n-1] != 1000 || rep.LastSpan != 8 {
		t.Fatalf("after the restart the newest point holds %v bytes over %v seconds (last span %d), want 1000 over 8", rep.Series.Out[n-1], rep.Series.Secs[n-1], rep.LastSpan)
	}
	day, err := second.report("24h", hourBoundary.Add(31*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if day.LastSpan != 22 || day.Totals.Out != 2400 {
		t.Fatalf("24h: last span %d, out %d; want 22 and 2400", day.LastSpan, day.Totals.Out)
	}
}

// A history whose dimension table is larger than the engine keeps is refused.
func TestTrafficHistoryRejectsAnOversizedDimensionTable(t *testing.T) {
	defer func(n int) { maxTrafficDims = n }(maxTrafficDims)
	maxTrafficDims = 2
	dir := t.TempDir()
	doc := `{"version":1,"dims":["host:a","host:b","host:c"],"levels":[{"frames":[{"t":1800000000,"s":10,"out":5,"d":[{"i":2,"out":5}]}]},{},{}],"lastSample":1800000010}`
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestTraffic(t, dir)
	if len(ts.dims) != 0 || len(ts.levels[0].Frames) != 0 {
		t.Fatalf("loaded %d dims and %d frames from an oversized table", len(ts.dims), len(ts.levels[0].Frames))
	}
}
