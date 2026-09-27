package engine

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"quicgate/internal/wg"
)

// errVPNOnlyName ends a TLS handshake on a public listener for a host that is
// only served inside the WireGuard tunnel.
var errVPNOnlyName = errors.New("no certificate for this name here")

// flowLogger writes the forwarder's flow log (S31). "No record, no flow" means
// written: the record of an allowed flow has been handed to the log file
// before the flow is admitted, and a flow whose record cannot be written is
// refused. Queued in memory is not written: a full disk or a directory that
// cannot be created would otherwise lose every record while every flow went
// through (QG-07). Records of denied and ended flows are best effort, and what
// is lost of them is counted.
//
// An admission waits for its record outside the endpoint's lock (the manager
// releases it first), so a slow disk delays that one flow and nothing else.
// While the log cannot be written, LAN flows are refused at once instead of
// each waiting for a write; one admission at a time probes the log, and the
// first probe whose record is written in time switches admission back on. A
// best-effort record that happens to go through does not: the question is
// whether the log keeps up with admissions, and only an admission's record
// answers it. A record whose admission gave up waiting is never left in the
// log as a plain "allow": the log says the flow was refused (L-35).
type flowLogger struct {
	write   func([]byte) error // replaced in tests
	queue   chan flowItem
	wait    time.Duration // how long one admission waits for its record; 0 means flowWriteWait
	dropped atomic.Uint64 // best-effort records not written, and allowed flows refused for want of a record
	failed  atomic.Bool
	probing atomic.Bool  // one admission is trying the failed log
	lastErr atomic.Value // string
	fullAt  atomic.Int64 // when the full queue was last reported, unix seconds
}

// flowItem is one queued record. state belongs to a record an admission waits
// for, and settles who decides what the log says about it: the writer claims
// the item before writing it, and an admission that times out claims it
// instead, so that the log never says "allow" for a flow that was refused.
type flowItem struct {
	rec   wg.FlowRecord
	done  chan error // set for a record that an admission waits for
	state *atomic.Int32
}

const (
	itemQueued        = iota
	itemWriting       // the writer has it
	itemWritten       // written as it was queued: the admission takes the result
	itemAbandoned     // the admission gave up before the writer got to it: written as a refusal
	itemAbandonedLate // the admission gave up while it was being written: a refusal follows the allow line
)

// flowWriteWait bounds how long one admission waits for its record. A log
// that is this slow counts as failing.
const flowWriteWait = 2 * time.Second

// flowLogFullEvery spaces the log lines about a full queue, in seconds.
const flowLogFullEvery = 60

func newFlowLogger(dir string) *flowLogger {
	out := &lumberjack.Logger{Filename: dir + "/logs/vpn-flows.log", MaxSize: 20, MaxBackups: 5, Compress: true}
	l := &flowLogger{queue: make(chan flowItem, 2048)}
	l.write = func(line []byte) error { _, err := out.Write(line); return err }
	go l.run()
	return l
}

func (l *flowLogger) waitFor() time.Duration {
	if l.wait > 0 {
		return l.wait
	}
	return flowWriteWait
}

// refused is the record of an allowed flow as the log must show it when the
// admission gave up waiting for the record: the flow never happened.
func refused(rec wg.FlowRecord) wg.FlowRecord {
	rec.Verdict, rec.Reason = "deny", "the flow log took too long: the flow was refused"
	return rec
}

func (l *flowLogger) writeRecord(rec wg.FlowRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return l.write(append(data, '\n'))
}

func (l *flowLogger) run() {
	for item := range l.queue {
		rec := item.rec
		waited := item.done != nil
		if waited && !item.state.CompareAndSwap(itemQueued, itemWriting) {
			rec = refused(rec) // the admission is gone
		}
		err := l.writeRecord(rec)
		if err != nil {
			if !l.failed.Swap(true) {
				log.Printf("vpn: the flow log cannot be written, LAN flows are refused until it can: %v", err)
			}
			l.lastErr.Store(err.Error())
			if !waited {
				l.dropped.Add(1)
			}
		}
		if waited {
			switch {
			case item.state.CompareAndSwap(itemWriting, itemWritten):
				if err == nil && l.failed.Swap(false) {
					log.Printf("vpn: the flow log can be written again")
				}
			case item.state.Load() == itemAbandonedLate && err == nil:
				// The allow line is in the log; the line that follows says what
				// became of the flow.
				_ = l.writeRecord(refused(item.rec))
			}
			item.done <- err
		}
	}
}

// record reports whether the record was taken. For an allowed flow that means
// written. It blocks for at most the write wait, and not at all while the log
// is known to fail, except for the one admission at a time that probes it.
func (l *flowLogger) record(rec wg.FlowRecord) bool {
	if rec.Verdict != "allow" {
		select {
		case l.queue <- flowItem{rec: rec}:
			return true
		default:
			l.dropped.Add(1)
			return false
		}
	}
	if l.failed.Load() {
		if !l.probing.CompareAndSwap(false, true) {
			return false
		}
		defer l.probing.Store(false)
	}
	item := flowItem{rec: rec, done: make(chan error, 1), state: new(atomic.Int32)}
	select {
	case l.queue <- item:
	default:
		// Refused for want of a record, and counted: the queue is full, so
		// the record of this refusal would not fit either.
		l.dropped.Add(1)
		l.noteFull()
		return false
	}
	select {
	case err := <-item.done:
		return err == nil
	case <-time.After(l.waitFor()):
	}
	// Timed out. The writer may have finished this very moment.
	select {
	case err := <-item.done:
		return err == nil
	default:
	}
	if !item.state.CompareAndSwap(itemQueued, itemAbandoned) && !item.state.CompareAndSwap(itemWriting, itemAbandonedLate) {
		return <-item.done == nil // written: the writer is about to say so
	}
	l.failed.Store(true)
	l.lastErr.Store("writing a record took longer than " + l.waitFor().String())
	return false
}

// noteFull logs, at most once a minute, that allowed flows are refused
// because the queue is full.
func (l *flowLogger) noteFull() {
	now := time.Now().Unix()
	if last := l.fullAt.Load(); now-last >= flowLogFullEvery && l.fullAt.CompareAndSwap(last, now) {
		log.Printf("vpn: the flow log queue is full: allowed LAN flows are refused until it drains (each is counted as a dropped record)")
	}
}

// FlowLogDropped reports how many flow records were lost: best-effort records
// the log could not take, allowed flows refused for want of a record, and
// deny records suppressed by the per-peer rate limit.
func (e *Engine) FlowLogDropped() uint64 {
	n := e.wg.FlowRecordsSuppressed()
	if e.flowLog != nil {
		n += e.flowLog.dropped.Load()
	}
	return n
}

// FlowLogError says why the flow log cannot be written, or "" when it can.
// While it cannot, LAN flows are refused.
func (e *Engine) FlowLogError() string {
	if e.flowLog == nil || !e.flowLog.failed.Load() {
		return ""
	}
	if s, _ := e.flowLog.lastErr.Load().(string); s != "" {
		return s
	}
	return "unknown error"
}

// ParseProtectedEndpoints reads the wg_protected_endpoints setting: addresses
// and address:port pairs, separated by commas, spaces or newlines (S48).
func ParseProtectedEndpoints(raw string) (addrs []netip.Addr, endpoints []netip.AddrPort, err error) {
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' }) {
		if ap, perr := netip.ParseAddrPort(tok); perr == nil && ap.Addr().Is4() {
			endpoints = append(endpoints, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			continue
		}
		a, perr := netip.ParseAddr(tok)
		if perr != nil || !a.Unmap().Is4() {
			return nil, nil, errors.New(tok + " is not an IPv4 address or address:port")
		}
		addrs = append(addrs, a.Unmap())
	}
	return addrs, endpoints, nil
}

// guardTTL is how long a guard function's answer is kept. The forwarder asks
// on every admission, and reading the interfaces, the routing table and the
// listeners each time made admission expensive under the endpoint's lock
// (M-15). A reload builds a new guard, so what a reload changed is seen at
// once; what changes underneath quicgate is seen within this long.
const guardTTL = 30 * time.Second

// memo returns load's answer, asking load again once the answer is ttl old.
// Callers must treat the answer as read-only: they share it.
func memo[T any](ttl time.Duration, load func() T) func() T {
	var mu sync.Mutex
	var at time.Time
	var val T
	return func() T {
		mu.Lock()
		defer mu.Unlock()
		if at.IsZero() || time.Since(at) >= ttl {
			val, at = load(), time.Now()
		}
		return val
	}
}

// wgGuard tells the forwarder what it must know about this machine (S48): its
// own addresses, the networks it is really on, the ports quicgate itself
// listens on, and the aliases the operator declared.
func (e *Engine) wgGuard() wg.Guard {
	addrs, endpoints, _ := ParseProtectedEndpoints(e.store.GetSetting("wg_protected_endpoints", ""))
	return wg.Guard{
		OwnAddrs: memo(guardTTL, func() []netip.Addr {
			var out []netip.Addr
			for _, a := range e.ban.own.list() {
				if ip, err := netip.ParseAddr(a.IP); err == nil {
					out = append(out, ip.Unmap())
				}
			}
			// In bridge networking the published ports live on the gateway's
			// address, which quicgate cannot see as its own. Treat it as such.
			if gw, ok := defaultGateway(); ok {
				out = append(out, gw)
			}
			return out
		}),
		OwnNets: memo(guardTTL, func() []netip.Prefix {
			var out []netip.Prefix
			ifaddrs, err := net.InterfaceAddrs()
			if err != nil {
				return nil
			}
			for _, a := range ifaddrs {
				if n, ok := a.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
						ones, _ := n.Mask.Size()
						if p, err := ip.Unmap().Prefix(ones); err == nil {
							out = append(out, p)
						}
					}
				}
			}
			return out
		}),
		ListenerPorts:      memo(guardTTL, e.listenerPorts),
		ProtectedAddrs:     addrs,
		ProtectedEndpoints: endpoints,
	}
}

// listenerPorts lists every port quicgate itself listens on: the proxy's, the
// WireGuard endpoint's, the admin UI's and every stream's.
func (e *Engine) listenerPorts() []uint16 {
	var out []uint16
	for _, p := range e.ReservedPorts() {
		out = append(out, uint16(p))
	}
	if p := portOf(e.cfg.AdminAddr); p > 0 {
		out = append(out, uint16(p))
	}
	for _, l := range e.streams.listeners() {
		last := l.stream.ListenPort
		if l.stream.ListenPortEnd > last {
			last = l.stream.ListenPortEnd
		}
		for p := l.stream.ListenPort; p <= last && p <= 65535; p++ {
			out = append(out, uint16(p))
		}
	}
	return out
}

// ListenerPorts is listenerPorts for the admin API, which refuses a site
// endpoint that names one of quicgate's own listeners.
func (e *Engine) ListenerPorts() []uint16 { return e.listenerPorts() }

// defaultGateway reads the IPv4 default gateway from /proc/net/route. In a
// container on a bridge network that is the Docker host, where quicgate's
// published ports live. On a machine without that file there is none to add.
func defaultGateway() (netip.Addr, bool) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" || len(f[2]) != 8 {
			continue
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(f[2][i*2:i*2+2], 16, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			b[3-i] = byte(v) // little endian
		}
		return netip.AddrFrom4(b), true
	}
	return netip.Addr{}, false
}
