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
// While the log cannot be written, LAN flows are refused at once instead of
// each waiting for a write. The records of those refusals are still tried, so
// the first one that succeeds switches admission back on.
type flowLogger struct {
	write   func([]byte) error // replaced in tests
	queue   chan flowItem
	dropped atomic.Uint64 // best-effort records that were not written
	failed  atomic.Bool
	lastErr atomic.Value // string
}

type flowItem struct {
	rec  wg.FlowRecord
	done chan error // set for a record that an admission waits for
}

// flowWriteWait bounds how long one admission waits for its record. It is
// held with the endpoint's lock, so it is short; a log that is this slow
// counts as failing.
const flowWriteWait = 2 * time.Second

func newFlowLogger(dir string) *flowLogger {
	out := &lumberjack.Logger{Filename: dir + "/logs/vpn-flows.log", MaxSize: 20, MaxBackups: 5, Compress: true}
	l := &flowLogger{queue: make(chan flowItem, 2048)}
	l.write = func(line []byte) error { _, err := out.Write(line); return err }
	go l.run()
	return l
}

func (l *flowLogger) run() {
	for item := range l.queue {
		data, err := json.Marshal(item.rec)
		if err == nil {
			err = l.write(append(data, '\n'))
		}
		if err != nil {
			if !l.failed.Swap(true) {
				log.Printf("vpn: the flow log cannot be written, LAN flows are refused until it can: %v", err)
			}
			l.lastErr.Store(err.Error())
			if item.done == nil {
				l.dropped.Add(1)
			}
		} else if l.failed.Swap(false) {
			log.Printf("vpn: the flow log can be written again")
		}
		if item.done != nil {
			item.done <- err
		}
	}
}

// record reports whether the record was taken. For an allowed flow that means
// written. It blocks for at most flowWriteWait, and not at all while the log
// is known to fail.
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
		return false
	}
	item := flowItem{rec: rec, done: make(chan error, 1)}
	select {
	case l.queue <- item:
	default:
		return false
	}
	select {
	case err := <-item.done:
		return err == nil
	case <-time.After(flowWriteWait):
		l.failed.Store(true)
		l.lastErr.Store("writing a record took longer than " + flowWriteWait.String())
		return false
	}
}

// FlowLogDropped reports how many best-effort flow records were lost.
func (e *Engine) FlowLogDropped() uint64 {
	if e.flowLog == nil {
		return 0
	}
	return e.flowLog.dropped.Load()
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

// wgGuard tells the forwarder what it must know about this machine (S48): its
// own addresses, the networks it is really on, the ports quicgate itself
// listens on, and the aliases the operator declared.
func (e *Engine) wgGuard() wg.Guard {
	addrs, endpoints, _ := ParseProtectedEndpoints(e.store.GetSetting("wg_protected_endpoints", ""))
	return wg.Guard{
		OwnAddrs: func() []netip.Addr {
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
		},
		OwnNets: func() []netip.Prefix {
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
		},
		ListenerPorts: func() []uint16 {
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
		},
		ProtectedAddrs:     addrs,
		ProtectedEndpoints: endpoints,
	}
}

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
