package engine

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"gopkg.in/natefinch/lumberjack.v2"

	"quicgate/internal/wg"
)

// errVPNOnlyName ends a TLS handshake on a public listener for a host that is
// only served inside the WireGuard tunnel.
var errVPNOnlyName = errors.New("no certificate for this name here")

// flowLogger writes the forwarder's flow log (S31). The record of an allowed
// flow is part of its admission: when it cannot be queued, the flow is
// refused, so every LAN flow that was allowed has a record. Records of denied
// and ended flows are best effort, and what is dropped is counted.
type flowLogger struct {
	out     *lumberjack.Logger
	queue   chan wg.FlowRecord
	dropped atomic.Uint64
}

func newFlowLogger(dir string) *flowLogger {
	l := &flowLogger{
		out:   &lumberjack.Logger{Filename: dir + "/logs/vpn-flows.log", MaxSize: 20, MaxBackups: 5, Compress: true},
		queue: make(chan wg.FlowRecord, 2048),
	}
	go func() {
		for rec := range l.queue {
			if data, err := json.Marshal(rec); err == nil {
				_, _ = l.out.Write(append(data, '\n'))
			}
		}
	}()
	return l
}

// record queues one line and reports whether it was taken. It never blocks.
func (l *flowLogger) record(rec wg.FlowRecord) bool {
	select {
	case l.queue <- rec:
		return true
	default:
		if rec.Verdict != "allow" {
			l.dropped.Add(1)
		}
		return false
	}
}

// FlowLogDropped reports how many best-effort flow records were dropped.
func (e *Engine) FlowLogDropped() uint64 {
	if e.flowLog == nil {
		return 0
	}
	return e.flowLog.dropped.Load()
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
