package engine

// Traffic history for the overview dashboard.
//
// The data plane only adds to atomic counters. Every 10 seconds a sampler turns
// them into a frame (the traffic of that interval) and rolls frames up into
// 5-minute and hourly frames, so the dashboard can draw the last hour, day or
// week without the request path doing any extra work. Everything held is
// bounded: hosts are the configured routes, ports are the listeners, countries
// are ISO codes, and each resolution keeps a fixed number of frames. The
// history is saved in the data directory every few minutes and at shutdown, so
// a restart or an upgrade does not wipe the charts.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// sampleStep is the length of the finest frame, in seconds.
const sampleStep = 10

// trafficSaveInterval is how often the sampler writes the history to disk.
const trafficSaveInterval = 5 * time.Minute

// historyLevels are the resolutions kept: an hour of 10-second frames, a day of
// 5-minute frames and a week of hourly frames.
var historyLevels = [3]struct {
	step   int64
	frames int
}{{sampleStep, 360}, {300, 288}, {3600, 168}}

// trafficRanges maps the dashboard's ranges to a resolution and a point count.
var trafficRanges = map[string]struct {
	level  int
	points int64
	spark  int64 // points per sparkline point
}{
	"1h":  {0, 360, 6},
	"6h":  {1, 72, 2},
	"24h": {1, 288, 6},
	"7d":  {2, 168, 3},
}

// blockReason says which quicgate control refused a request or connection.
type blockReason uint8

const (
	blockNone         blockReason = iota
	blockAccessList               // an access list refused the address or the credentials
	blockBanned                   // the client is auto-banned
	blockRateLimit                // the client went over the host's rate limit
	blockExploit                  // the exploit filter, or a path with dot segments
	blockBot                      // a blocked bot user agent
	blockClientCert               // no acceptable client certificate
	blockSSO                      // single sign-on refused the identity
	blockForwardAuth              // the forward-auth service refused the request
	blockStreamSource             // a stream's source filter refused the client
	numBlockReasons
)

var blockReasonNames = [numBlockReasons]string{"", "accessList", "banned", "rateLimit", "exploit", "bot", "clientCert", "sso", "forwardAuth", "streamSource"}

// latencyBounds are the upper bounds, in milliseconds, of the time-to-first-byte
// buckets. One more bucket holds everything slower.
var latencyBounds = [...]float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const numLatencyBuckets = len(latencyBounds) + 1

func latencyBucket(d time.Duration) int {
	ms := float64(d) / float64(time.Millisecond)
	for i, b := range latencyBounds {
		if ms <= b {
			return i
		}
	}
	return len(latencyBounds)
}

// percentile estimates the q-quantile (0 to 1) of the samples counted in b, in
// milliseconds, interpolating inside the bucket it falls in. It returns -1 when
// there are no samples. The open-ended last bucket reports its lower bound.
func percentile(b *[numLatencyBuckets]uint64, q float64) float64 {
	var total uint64
	for _, n := range b {
		total += n
	}
	if total == 0 {
		return -1
	}
	rank := q * float64(total)
	var seen float64
	for i, n := range b {
		if n == 0 {
			continue
		}
		if seen+float64(n) >= rank {
			lo := 0.0
			if i > 0 {
				lo = latencyBounds[i-1]
			}
			if i == len(latencyBounds) {
				return lo
			}
			return lo + (latencyBounds[i]-lo)*(rank-seen)/float64(n)
		}
		seen += float64(n)
	}
	return latencyBounds[len(latencyBounds)-1]
}

// delta is how much a cumulative counter grew. A counter that went down was
// restarted, so everything it holds is new.
func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// ---- listener counters ----

// portCounters account the traffic on one listener's client-facing sockets.
// The methods are nil-safe, so code without statistics needs no checks.
type portCounters struct {
	in, out  atomic.Uint64 // bytes received from and sent to clients
	accepted atomic.Uint64 // connections (UDP: client sessions) accepted
	active   atomic.Int64  // connections open now
}

func (p *portCounters) received(n int) {
	if p != nil && n > 0 {
		p.in.Add(uint64(n))
	}
}

func (p *portCounters) sent(n int) {
	if p != nil && n > 0 {
		p.out.Add(uint64(n))
	}
}

func (p *portCounters) opened() {
	if p != nil {
		p.accepted.Add(1)
		p.active.Add(1)
	}
}

func (p *portCounters) closed() {
	if p != nil {
		p.active.Add(-1)
	}
}

// countedConn counts the bytes a client connection carries, TLS records and
// HTTP framing included. A stream splice through it copies in user space
// instead of using splice(2), which is the price of per-read accounting.
type countedConn struct {
	net.Conn
	c    *portCounters
	done atomic.Bool
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.c.received(n)
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.c.sent(n)
	return n, err
}

func (c *countedConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.c.closed()
	}
	return c.Conn.Close()
}

// countedListener wraps every connection it accepts in a countedConn.
type countedListener struct {
	net.Listener
	c *portCounters
}

func (l countedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.c.opened()
	return &countedConn{Conn: conn, c: l.c}, nil
}

// maxTrackedQUIC caps the HTTP/3 connections followed for byte counts. Past it
// new connections are served but not counted.
const maxTrackedQUIC = 65536

// quicTracker follows open HTTP/3 connections. quic-go counts their bytes
// itself, so each drain adds what every connection carried since the last one.
type quicTracker struct {
	mu    sync.Mutex
	port  *portCounters
	conns map[*quic.Conn][2]uint64 // bytes received and sent at the last drain
}

func (q *quicTracker) track(c *quic.Conn) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.port == nil || len(q.conns) >= maxTrackedQUIC {
		return
	}
	if q.conns == nil {
		q.conns = map[*quic.Conn][2]uint64{}
	}
	q.conns[c] = [2]uint64{}
	q.port.opened()
}

// drain moves the bytes every tracked connection carried since the last drain
// into the listener's counters and forgets the connections that have closed.
func (q *quicTracker) drain() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for c, seen := range q.conns {
		st := c.ConnectionStats()
		q.port.in.Add(delta(st.BytesReceived, seen[0]))
		q.port.out.Add(delta(st.BytesSent, seen[1]))
		if c.Context().Err() != nil {
			delete(q.conns, c)
			q.port.closed()
			continue
		}
		q.conns[c] = [2]uint64{st.BytesReceived, st.BytesSent}
	}
}

// ---- history ----

// frame is the traffic of one interval. In and Out are bytes on the client side
// of every listener; host dimensions count response body bytes.
type frame struct {
	Start    int64                     `json:"t"`
	In       uint64                    `json:"in,omitempty"`
	Out      uint64                    `json:"out,omitempty"`
	Requests uint64                    `json:"rq,omitempty"`
	Status   [4]uint64                 `json:"st"` // 2xx, 3xx, 4xx, 5xx
	Proto    [3]uint64                 `json:"pr"` // HTTP/1.x, HTTP/2, HTTP/3
	Blocked  [numBlockReasons]uint64   `json:"bl"`
	Latency  [numLatencyBuckets]uint64 `json:"lt"`
	Conns    uint64                    `json:"cn,omitempty"`
	Active   int64                     `json:"ac,omitempty"` // the most connections open at any sample
	Dims     []dimFrame                `json:"d,omitempty"`
}

// dimFrame is one host's, port's or country's share of a frame.
type dimFrame struct {
	ID     uint32 `json:"i"`
	In     uint64 `json:"in,omitempty"`
	Out    uint64 `json:"out,omitempty"`
	Count  uint64 `json:"n,omitempty"`  // requests (hosts, countries) or connections (ports)
	Errors uint64 `json:"e,omitempty"`  // 5xx responses (hosts)
	Active int64  `json:"ac,omitempty"` // most connections open (ports)
}

// addCounters adds g's totals, not its dimensions, to f.
func (f *frame) addCounters(g *frame) {
	f.In += g.In
	f.Out += g.Out
	f.Requests += g.Requests
	for i := range f.Status {
		f.Status[i] += g.Status[i]
	}
	for i := range f.Proto {
		f.Proto[i] += g.Proto[i]
	}
	for i := range f.Blocked {
		f.Blocked[i] += g.Blocked[i]
	}
	for i := range f.Latency {
		f.Latency[i] += g.Latency[i]
	}
	f.Conns += g.Conns
	f.Active = max(f.Active, g.Active)
}

func (d *dimFrame) add(g dimFrame) {
	d.In += g.In
	d.Out += g.Out
	d.Count += g.Count
	d.Errors += g.Errors
	d.Active = max(d.Active, g.Active)
}

// merge adds all of g to f.
func (f *frame) merge(g *frame) {
	f.addCounters(g)
next:
	for _, d := range g.Dims {
		for i := range f.Dims {
			if f.Dims[i].ID == d.ID {
				f.Dims[i].add(d)
				continue next
			}
		}
		f.Dims = append(f.Dims, d)
	}
}

// historyLevel is one resolution of the history: completed frames, oldest
// first, and the frame still being filled.
type historyLevel struct {
	Frames  []frame `json:"frames"`
	Pending *frame  `json:"pending,omitempty"`
	step    int64
	cap     int
}

func (l *historyLevel) push(f frame) {
	if len(l.Frames) >= l.cap {
		n := copy(l.Frames, l.Frames[len(l.Frames)-l.cap+1:])
		l.Frames = l.Frames[:n]
	}
	l.Frames = append(l.Frames, f)
}

// add merges f, a frame of a finer level, into the pending frame, completing
// the pending frame first when f belongs to a later interval. It returns the
// frame it completed, if any.
func (l *historyLevel) add(f *frame) *frame {
	start := f.Start - f.Start%l.step
	var done *frame
	if l.Pending != nil && l.Pending.Start != start {
		done = l.Pending
		l.push(*done)
		l.Pending = nil
	}
	if l.Pending == nil {
		l.Pending = &frame{Start: start}
	}
	l.Pending.merge(f)
	return done
}

// counterSnapshot is every cumulative counter at one moment.
type counterSnapshot struct {
	requests uint64
	status   [4]uint64
	proto    [3]uint64
	blocked  [numBlockReasons]uint64
	latency  [numLatencyBuckets]uint64
	dims     map[string]dimCounts // "host:app.example", "port:tcp:443", "country:NL"
}

type dimCounts struct {
	in, out, count, errs uint64
	active               int64
}

// maxTrafficDims bounds the dimension table. Its keys come from configuration
// and country codes, so this is only a backstop for a very long uptime full of
// configuration changes; unused entries are dropped before it is reached. A
// variable so tests can use a small table.
var maxTrafficDims = 4096

// maxCountries bounds the per-country counters (there are about 250 codes).
const maxCountries = 300

// trafficStats keeps the traffic history. Request counters live in the access
// log, which already sees every request; the rest is counted here.
type trafficStats struct {
	log     *accessLogger
	ban     *banManager    // requests refused because the client is banned
	streams *StreamManager // stream clients refused by a source filter
	geo     *geoDB
	path    string // history file; empty keeps nothing on disk

	portsMu sync.Mutex
	ports   map[string]*portCounters // by listener: "tcp:443", "udp:443", "tcp:2222" (a stream's first port)
	quic    quicTracker

	countryMu sync.Mutex
	countries map[string]uint64 // requests by client country code, "LAN" or "unknown"

	mu         sync.Mutex // guards everything below
	dims       []string   // dimension keys by id
	dimIDs     map[string]uint32
	prev       counterSnapshot
	levels     [3]historyLevel
	lastSample int64 // unix end of the newest frame
	lastSave   time.Time
}

func newTrafficStats(l *accessLogger, ban *banManager, streams *StreamManager, geo *geoDB, dataDir string) *trafficStats {
	t := &trafficStats{
		log: l, ban: ban, streams: streams, geo: geo,
		ports:     map[string]*portCounters{},
		countries: map[string]uint64{},
		dimIDs:    map[string]uint32{},
	}
	for i := range t.levels {
		t.levels[i].step, t.levels[i].cap = historyLevels[i].step, historyLevels[i].frames
	}
	if dataDir != "" {
		t.path = filepath.Join(dataDir, "traffic.json")
		t.load()
	}
	return t
}

// port returns the counters for a listener key, creating them on first use.
func (t *trafficStats) port(key string) *portCounters {
	if t == nil {
		return nil
	}
	t.portsMu.Lock()
	defer t.portsMu.Unlock()
	p, ok := t.ports[key]
	if !ok {
		p = &portCounters{}
		t.ports[key] = p
	}
	return p
}

// quicConnContext returns an http3.Server ConnContext hook that counts every
// HTTP/3 connection against the listener key.
func (t *trafficStats) quicConnContext(key string) func(context.Context, *quic.Conn) context.Context {
	p := t.port(key)
	t.quic.mu.Lock()
	t.quic.port = p
	t.quic.mu.Unlock()
	return func(ctx context.Context, c *quic.Conn) context.Context {
		t.quic.track(c)
		return ctx
	}
}

// countClient counts a request by the client's country, when a GeoIP database
// is loaded.
func (t *trafficStats) countClient(ip string) {
	if !t.geo.loaded() {
		return
	}
	t.countCountry(clientCountry(ip, t.geo.country))
}

// clientCountry names the country a client address belongs to: private,
// loopback and link-local addresses are "LAN", and an address the database
// does not place is "unknown".
func clientCountry(ip string, lookup func(net.IP) string) string {
	addr := net.ParseIP(ip)
	switch {
	case addr == nil:
		return "unknown"
	case addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast():
		return "LAN"
	}
	if code := lookup(addr); code != "" {
		return code
	}
	return "unknown"
}

func (t *trafficStats) countCountry(cc string) {
	t.countryMu.Lock()
	defer t.countryMu.Unlock()
	if _, ok := t.countries[cc]; ok || len(t.countries) < maxCountries {
		t.countries[cc]++
	}
}

// run samples on every 10-second boundary of the clock and saves the history
// every few minutes, until ctx ends.
func (t *trafficStats) run(ctx context.Context) {
	for {
		next := time.Now().Truncate(sampleStep * time.Second).Add(sampleStep * time.Second)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		t.sample(next)
		t.mu.Lock()
		due := time.Since(t.lastSave) >= trafficSaveInterval
		t.mu.Unlock()
		if due {
			if err := t.save(); err != nil {
				log.Printf("traffic: save history: %v", err)
			}
		}
	}
}

// sample closes the interval that ends at end: it stores what every counter
// added since the previous sample as a frame and rolls that frame up.
func (t *trafficStats) sample(end time.Time) {
	t.quic.drain()
	cur := t.read()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.dims)+len(cur.dims) > maxTrafficDims {
		t.compactDims()
	}
	f := t.diff(&cur)
	f.Start = end.Unix() - sampleStep
	t.prev = cur
	t.lastSample = end.Unix()
	t.levels[0].push(f)
	if done := t.levels[1].add(&f); done != nil {
		t.levels[2].add(done)
	}
}

func (t *trafficStats) read() counterSnapshot {
	l := t.log
	s := counterSnapshot{
		requests: l.total.Load(),
		status:   [4]uint64{l.status2xx.Load(), l.status3xx.Load(), l.status4xx.Load(), l.status5xx.Load()},
		dims:     map[string]dimCounts{},
	}
	for i := range s.proto {
		s.proto[i] = l.proto[i+1].Load()
	}
	for i := range s.blocked {
		s.blocked[i] = l.blocked[i].Load()
	}
	for i := range s.latency {
		s.latency[i] = l.latency[i].Load()
	}
	if t.ban != nil {
		s.blocked[blockBanned] += t.ban.refused.Load()
	}
	if t.streams != nil {
		s.blocked[blockStreamSource] += t.streams.refused.Load()
	}
	l.perHost.Range(func(k, v any) bool {
		hc := v.(*hostCounters)
		s.dims["host:"+k.(string)] = dimCounts{out: hc.bytes.Load(), count: hc.total.Load(), errs: hc.errs.Load()}
		return true
	})
	t.portsMu.Lock()
	for key, p := range t.ports {
		s.dims["port:"+key] = dimCounts{in: p.in.Load(), out: p.out.Load(), count: p.accepted.Load(), active: p.active.Load()}
	}
	t.portsMu.Unlock()
	t.countryMu.Lock()
	for cc, n := range t.countries {
		s.dims["country:"+cc] = dimCounts{count: n}
	}
	t.countryMu.Unlock()
	return s
}

// diff turns the growth since the previous snapshot into a frame. t.mu is held.
func (t *trafficStats) diff(cur *counterSnapshot) frame {
	p := &t.prev
	f := frame{Requests: delta(cur.requests, p.requests)}
	for i := range f.Status {
		f.Status[i] = delta(cur.status[i], p.status[i])
	}
	for i := range f.Proto {
		f.Proto[i] = delta(cur.proto[i], p.proto[i])
	}
	for i := range f.Blocked {
		f.Blocked[i] = delta(cur.blocked[i], p.blocked[i])
	}
	for i := range f.Latency {
		f.Latency[i] = delta(cur.latency[i], p.latency[i])
	}
	keys := make([]string, 0, len(cur.dims))
	for k := range cur.dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c, was := cur.dims[k], p.dims[k]
		d := dimFrame{In: delta(c.in, was.in), Out: delta(c.out, was.out), Count: delta(c.count, was.count),
			Errors: delta(c.errs, was.errs), Active: max(c.active, 0)}
		if strings.HasPrefix(k, "port:") {
			f.In += d.In
			f.Out += d.Out
			f.Conns += d.Count
			f.Active += d.Active
		}
		if d == (dimFrame{}) {
			continue
		}
		if len(t.dims) >= maxTrafficDims {
			if _, known := t.dimIDs[k]; !known {
				continue
			}
		}
		d.ID = t.dimID(k)
		f.Dims = append(f.Dims, d)
	}
	return f
}

// dimID returns the id of a dimension key, adding it to the table if needed.
// t.mu is held.
func (t *trafficStats) dimID(key string) uint32 {
	if id, ok := t.dimIDs[key]; ok {
		return id
	}
	id := uint32(len(t.dims))
	t.dims = append(t.dims, key)
	t.dimIDs[key] = id
	return id
}

// compactDims drops dimensions no frame refers to any more and renumbers the
// rest. t.mu is held.
func (t *trafficStats) compactDims() {
	used := make([]bool, len(t.dims))
	t.eachFrame(func(f *frame) {
		for _, d := range f.Dims {
			used[d.ID] = true
		}
	})
	remap := make([]uint32, len(t.dims))
	dims := make([]string, 0, len(t.dims))
	ids := map[string]uint32{}
	for id, key := range t.dims {
		if !used[id] {
			continue
		}
		if first, dup := ids[key]; dup {
			remap[id] = first
			continue
		}
		remap[id] = uint32(len(dims))
		ids[key] = remap[id]
		dims = append(dims, key)
	}
	t.eachFrame(func(f *frame) {
		var merged []dimFrame
	next:
		for _, d := range f.Dims {
			d.ID = remap[d.ID]
			for i := range merged {
				if merged[i].ID == d.ID {
					merged[i].add(d)
					continue next
				}
			}
			merged = append(merged, d)
		}
		f.Dims = merged
	})
	t.dims, t.dimIDs = dims, ids
}

func (t *trafficStats) eachFrame(fn func(*frame)) {
	for i := range t.levels {
		l := &t.levels[i]
		for j := range l.Frames {
			fn(&l.Frames[j])
		}
		if l.Pending != nil {
			fn(l.Pending)
		}
	}
}

// ---- report ----

// TrafficReport is the traffic over one of the dashboard's ranges. Series hold
// one value per step, oldest first, and null where there is no data (quicgate
// was not running). Byte series and totals are bytes on the client side of
// every listener, TLS and protocol framing included.
type TrafficReport struct {
	Range     string           `json:"range"`
	Step      int64            `json:"step"`     // seconds per point
	Start     int64            `json:"start"`    // unix time the first point starts
	LastSpan  int64            `json:"lastSpan"` // seconds of data in the last point, which may still be filling
	Series    TrafficSeries    `json:"series"`
	Totals    TrafficTotals    `json:"totals"`
	Ports     []PortTraffic    `json:"ports"`
	Hosts     []HostTraffic    `json:"hosts"`     // busiest first, at most 10
	Countries []CountryTraffic `json:"countries"` // busiest first, at most 10; empty without GeoIP
	GeoIP     bool             `json:"geoip"`
	Open      int64            `json:"open"`   // connections open now
	Banned    int              `json:"banned"` // addresses banned now
}

// TrafficSeries are the chart lines, one value per step.
type TrafficSeries struct {
	In        gapSeries `json:"in"`
	Out       gapSeries `json:"out"`
	Requests  gapSeries `json:"requests"`
	Status2xx gapSeries `json:"2xx"`
	Status3xx gapSeries `json:"3xx"`
	Status4xx gapSeries `json:"4xx"`
	Status5xx gapSeries `json:"5xx"`
	Blocked   gapSeries `json:"blocked"`
	Open      gapSeries `json:"open"` // the most connections open at once
	P50       gapSeries `json:"p50"`  // time to first byte, milliseconds
	P95       gapSeries `json:"p95"`
}

// TrafficTotals sum a whole range.
type TrafficTotals struct {
	In          uint64            `json:"in"`
	Out         uint64            `json:"out"`
	Requests    uint64            `json:"requests"`
	Status      map[string]uint64 `json:"status"`    // "2xx" to "5xx"
	Protocols   map[string]uint64 `json:"protocols"` // "HTTP/1.1", "HTTP/2", "HTTP/3"
	Blocked     map[string]uint64 `json:"blocked"`   // by reason
	Connections uint64            `json:"connections"`
	PeakOpen    int64             `json:"peakOpen"`
	P50         float64           `json:"p50"` // milliseconds; -1 without responses
	P95         float64           `json:"p95"`
	P99         float64           `json:"p99"`
}

// PortTraffic is one listener and what went through it.
type PortTraffic struct {
	Key         string    `json:"key"` // "tcp:443"
	Proto       string    `json:"proto"`
	Port        int       `json:"port"`
	PortEnd     int       `json:"portEnd,omitempty"`
	Service     string    `json:"service"`
	Detail      string    `json:"detail"`
	StreamID    int64     `json:"streamId,omitempty"`
	Docker      bool      `json:"docker,omitempty"`
	State       string    `json:"state"` // listening | failed
	Error       string    `json:"error,omitempty"`
	Exposed     *bool     `json:"exposed,omitempty"` // mapped on the router by UPnP; absent when UPnP is off
	In          uint64    `json:"in"`
	Out         uint64    `json:"out"`
	Connections uint64    `json:"connections"`
	Open        int64     `json:"open"`
	Spark       gapSeries `json:"spark"` // bytes per second, in and out together
}

// HostTraffic is one configured route's requests.
type HostTraffic struct {
	Name     string    `json:"name"` // domain, "*.suffix" or "_unmatched"
	Requests uint64    `json:"requests"`
	Out      uint64    `json:"out"`    // response body bytes
	Errors   uint64    `json:"errors"` // 5xx responses
	Spark    gapSeries `json:"spark"`  // requests per second
}

// CountryTraffic is the requests from one country.
type CountryTraffic struct {
	Code     string `json:"code"` // ISO 3166-1 alpha-2, "LAN" or "unknown"
	Requests uint64 `json:"requests"`
}

// gapSeries marshals to a JSON array with null for points without data, which
// it holds as negative values.
type gapSeries []float64

func (s gapSeries) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, 2+len(s)*6)
	b = append(b, '[')
	for i, v := range s {
		if i > 0 {
			b = append(b, ',')
		}
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			b = append(b, "null"...)
			continue
		}
		b = strconv.AppendFloat(b, v, 'f', -1, 64)
	}
	return append(b, ']'), nil
}

func round1(v float64) float64 {
	if v < 0 {
		return v
	}
	return math.Round(v*10) / 10
}

// report builds the report for a range as of now. ports lists the listeners to
// describe, with Key set; their numbers are filled in.
func (t *trafficStats) report(rng string, now time.Time, ports []PortTraffic) (TrafficReport, error) {
	spec, ok := trafficRanges[rng]
	if !ok {
		return TrafficReport{}, fmt.Errorf("unknown range %q: use 1h, 6h, 24h or 7d", rng)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	lvl := &t.levels[spec.level]
	step, n := lvl.step, spec.points
	// The newest point is the interval holding the newest completed sample.
	end := now.Unix() - now.Unix()%sampleStep
	if r := end % step; r != 0 {
		end += step - r
	}
	start := end - n*step

	slots := make([]frame, n)
	present := make([]bool, n)
	place := func(f *frame) {
		if f == nil || f.Start < start || f.Start >= end {
			return
		}
		i := (f.Start - start) / step
		slots[i].merge(f)
		present[i] = true
	}
	for i := range lvl.Frames {
		place(&lvl.Frames[i])
	}
	place(lvl.Pending)
	// Finer levels hold their newest frame back until it completes.
	for j := spec.level - 1; j >= 1; j-- {
		place(t.levels[j].Pending)
	}
	lastSpan := min(max(t.lastSample-(end-step), 0), step)
	span := func(i int64) int64 {
		if i == n-1 {
			return lastSpan
		}
		return step
	}

	if ports == nil {
		ports = []PortTraffic{}
	}
	rep := TrafficReport{Range: rng, Step: step, Start: start, LastSpan: lastSpan, Ports: ports, Hosts: []HostTraffic{}, Countries: []CountryTraffic{}}
	s := &rep.Series
	for _, sp := range []*gapSeries{&s.In, &s.Out, &s.Requests, &s.Status2xx, &s.Status3xx, &s.Status4xx, &s.Status5xx, &s.Blocked, &s.Open, &s.P50, &s.P95} {
		*sp = make(gapSeries, n)
	}
	var total frame
	dimTotals := map[uint32]*dimFrame{}
	for i := range slots {
		if !present[i] {
			for _, sp := range []gapSeries{s.In, s.Out, s.Requests, s.Status2xx, s.Status3xx, s.Status4xx, s.Status5xx, s.Blocked, s.Open, s.P50, s.P95} {
				sp[i] = -1
			}
			continue
		}
		f := &slots[i]
		total.addCounters(f)
		for _, d := range f.Dims {
			if dt := dimTotals[d.ID]; dt != nil {
				dt.add(d)
			} else {
				c := d
				dimTotals[d.ID] = &c
			}
		}
		s.In[i], s.Out[i], s.Requests[i] = float64(f.In), float64(f.Out), float64(f.Requests)
		s.Status2xx[i], s.Status3xx[i], s.Status4xx[i], s.Status5xx[i] = float64(f.Status[0]), float64(f.Status[1]), float64(f.Status[2]), float64(f.Status[3])
		var blocked uint64
		for _, b := range f.Blocked {
			blocked += b
		}
		s.Blocked[i], s.Open[i] = float64(blocked), float64(f.Active)
		s.P50[i], s.P95[i] = round1(percentile(&f.Latency, .50)), round1(percentile(&f.Latency, .95))
	}

	rep.Totals = TrafficTotals{
		In: total.In, Out: total.Out, Requests: total.Requests,
		Status:      map[string]uint64{"2xx": total.Status[0], "3xx": total.Status[1], "4xx": total.Status[2], "5xx": total.Status[3]},
		Protocols:   map[string]uint64{"HTTP/1.1": total.Proto[0], "HTTP/2": total.Proto[1], "HTTP/3": total.Proto[2]},
		Blocked:     map[string]uint64{},
		Connections: total.Conns, PeakOpen: total.Active,
		P50: round1(percentile(&total.Latency, .50)), P95: round1(percentile(&total.Latency, .95)), P99: round1(percentile(&total.Latency, .99)),
	}
	for i := blockNone + 1; i < numBlockReasons; i++ {
		rep.Totals.Blocked[blockReasonNames[i]] = total.Blocked[i]
	}

	// Pick the dimensions to describe, then collect their sparklines.
	value := map[uint32]func(dimFrame) uint64{}
	type hostPick struct {
		id uint32
		h  HostTraffic
	}
	var picks []hostPick
	for id, d := range dimTotals {
		key := t.dims[id]
		switch {
		case strings.HasPrefix(key, "host:"):
			picks = append(picks, hostPick{id, HostTraffic{Name: key[len("host:"):], Requests: d.Count, Out: d.Out, Errors: d.Errors}})
		case strings.HasPrefix(key, "country:"):
			rep.Countries = append(rep.Countries, CountryTraffic{Code: key[len("country:"):], Requests: d.Count})
		}
	}
	sort.Slice(picks, func(a, b int) bool {
		if picks[a].h.Requests != picks[b].h.Requests {
			return picks[a].h.Requests > picks[b].h.Requests
		}
		return picks[a].h.Name < picks[b].h.Name
	})
	picks = picks[:min(len(picks), 10)]
	for _, p := range picks {
		rep.Hosts = append(rep.Hosts, p.h)
		value[p.id] = func(d dimFrame) uint64 { return d.Count }
	}
	sort.Slice(rep.Countries, func(a, b int) bool {
		if rep.Countries[a].Requests != rep.Countries[b].Requests {
			return rep.Countries[a].Requests > rep.Countries[b].Requests
		}
		return rep.Countries[a].Code < rep.Countries[b].Code
	})
	rep.Countries = rep.Countries[:min(len(rep.Countries), 10)]
	for i := range rep.Ports {
		if id, ok := t.dimIDs["port:"+rep.Ports[i].Key]; ok {
			if d := dimTotals[id]; d != nil {
				rep.Ports[i].In, rep.Ports[i].Out, rep.Ports[i].Connections = d.In, d.Out, d.Count
			}
			value[id] = func(d dimFrame) uint64 { return d.In + d.Out }
		}
	}
	groups := (n + spec.spark - 1) / spec.spark
	sums := map[uint32][]float64{}
	for id := range value {
		sums[id] = make([]float64, groups)
	}
	covered := make([]int64, groups)
	for i := range slots {
		if !present[i] {
			continue
		}
		g := int64(i) / spec.spark
		covered[g] += span(int64(i))
		for _, d := range slots[i].Dims {
			if fn := value[d.ID]; fn != nil {
				sums[d.ID][g] += float64(fn(d))
			}
		}
	}
	sparkOf := map[uint32]gapSeries{}
	for id, sum := range sums {
		sp := make(gapSeries, groups)
		for g := range sum {
			if covered[g] == 0 {
				sp[g] = -1
				continue
			}
			sp[g] = sum[g] / float64(covered[g])
		}
		sparkOf[id] = sp
	}
	for j, p := range picks {
		rep.Hosts[j].Spark = sparkOf[p.id]
	}
	empty := make(gapSeries, groups)
	for g := range empty {
		empty[g] = -1
		if covered[g] > 0 {
			empty[g] = 0
		}
	}
	t.portsMu.Lock()
	for i := range rep.Ports {
		p := &rep.Ports[i]
		p.Spark = empty
		if id, ok := t.dimIDs["port:"+p.Key]; ok {
			if sp, ok := sparkOf[id]; ok {
				p.Spark = sp
			}
		}
		if c := t.ports[p.Key]; c != nil {
			p.Open = max(c.active.Load(), 0)
		}
	}
	for _, c := range t.ports {
		rep.Open += max(c.active.Load(), 0)
	}
	t.portsMu.Unlock()
	rep.GeoIP = t.geo.loaded()
	if t.ban != nil {
		rep.Banned = t.ban.bannedCount()
	}
	return rep, nil
}

// ---- persistence ----

// trafficFile is the history as saved on disk.
type trafficFile struct {
	Version    int             `json:"version"`
	Dims       []string        `json:"dims"`
	Levels     [3]historyLevel `json:"levels"`
	LastSample int64           `json:"lastSample"`
}

const trafficFileVersion = 1

// save writes the history next to the database, atomically.
func (t *trafficStats) save() error {
	if t.path == "" {
		return nil
	}
	t.mu.Lock()
	data, err := json.Marshal(trafficFile{Version: trafficFileVersion, Dims: t.dims, Levels: t.levels, LastSample: t.lastSample})
	t.lastSave = time.Now()
	t.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// load restores a saved history. A missing file starts empty; a damaged one,
// or one from another format version, is logged and ignored.
func (t *trafficStats) load() {
	data, err := os.ReadFile(t.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("traffic: cannot read the saved history: %v", err)
		}
		return
	}
	var tf trafficFile
	if err := json.Unmarshal(data, &tf); err != nil || tf.Version != trafficFileVersion {
		log.Printf("traffic: ignoring the saved history in %s (damaged or from another version)", t.path)
		return
	}
	valid := func(f *frame, step int64) bool {
		if f.Start <= 0 || f.Start%step != 0 || len(f.Dims) > maxTrafficDims {
			return false
		}
		for _, d := range f.Dims {
			if int(d.ID) >= len(tf.Dims) {
				return false
			}
		}
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.levels {
		l := &t.levels[i]
		saved := tf.Levels[i]
		for j := range saved.Frames {
			if valid(&saved.Frames[j], l.step) {
				l.push(saved.Frames[j])
			}
		}
		if saved.Pending != nil && valid(saved.Pending, l.step) {
			l.Pending = saved.Pending
		}
	}
	t.dims = tf.Dims
	t.lastSample = tf.LastSample
	t.compactDims()
}

// ---- metrics ----

// promText renders the listener, protocol and refusal counters in Prometheus
// exposition format.
func (t *trafficStats) promText() string {
	var b strings.Builder
	t.portsMu.Lock()
	keys := make([]string, 0, len(t.ports))
	for k := range t.ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type row struct {
		key               string
		in, out, accepted uint64
		open              int64
	}
	rows := make([]row, 0, len(keys))
	for _, k := range keys {
		p := t.ports[k]
		rows = append(rows, row{k, p.in.Load(), p.out.Load(), p.accepted.Load(), max(p.active.Load(), 0)})
	}
	t.portsMu.Unlock()
	metric := func(name, kind, help string, each func(r row) string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
		for _, r := range rows {
			fmt.Fprintf(&b, "%s{listener=%q} %s\n", name, r.key, each(r))
		}
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	metric("quicgate_listener_received_bytes_total", "counter", "Bytes received from clients per listener (HTTP/3 is updated every 10 seconds).", func(r row) string { return u(r.in) })
	metric("quicgate_listener_sent_bytes_total", "counter", "Bytes sent to clients per listener (HTTP/3 is updated every 10 seconds).", func(r row) string { return u(r.out) })
	metric("quicgate_listener_connections_total", "counter", "Connections accepted per listener (UDP streams: client sessions).", func(r row) string { return u(r.accepted) })
	metric("quicgate_listener_open_connections", "gauge", "Connections open now per listener.", func(r row) string { return strconv.FormatInt(r.open, 10) })

	l := t.log
	fmt.Fprintf(&b, "# HELP quicgate_requests_by_protocol_total Requests by HTTP version.\n# TYPE quicgate_requests_by_protocol_total counter\n")
	for i, name := range []string{"HTTP/1.1", "HTTP/2", "HTTP/3"} {
		fmt.Fprintf(&b, "quicgate_requests_by_protocol_total{protocol=%q} %d\n", name, l.proto[i+1].Load())
	}
	fmt.Fprintf(&b, "# HELP quicgate_blocked_total Requests and stream clients refused by quicgate, by reason.\n# TYPE quicgate_blocked_total counter\n")
	for i := blockNone + 1; i < numBlockReasons; i++ {
		n := l.blocked[i].Load()
		switch {
		case i == blockBanned && t.ban != nil:
			n += t.ban.refused.Load()
		case i == blockStreamSource && t.streams != nil:
			n += t.streams.refused.Load()
		}
		fmt.Fprintf(&b, "quicgate_blocked_total{reason=%q} %d\n", blockReasonNames[i], n)
	}
	return b.String()
}
