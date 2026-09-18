package engine

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// ParseBanExempt reads the never-ban list: addresses and CIDR ranges separated
// by commas, spaces or newlines. A bare address stands for itself. An entry
// that is neither is an error, so a typo is not a silent gap in the list.
func ParseBanExempt(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r'
	}) {
		if a, err := netip.ParseAddr(tok); err == nil {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return out, fmt.Errorf("%q is not an address or a CIDR range", tok)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// OwnAddress is one address quicgate treats as its own, and where it was found.
type OwnAddress struct {
	IP     string `json:"ip"`
	Source string `json:"source"` // "interface" or "router"
}

// ownAddrTTL is how long the own addresses are kept before they are read
// again. Refusals can come in floods; the interfaces are not read for each.
const ownAddrTTL = time.Minute

// ownAddresses finds this machine's addresses: the ones on its interfaces,
// and the public address of the router when UPnP knows it. Clients on the LAN
// that reach quicgate through the router's public address arrive from that
// address, so a monitor at home can otherwise ban the whole household.
type ownAddresses struct {
	mu       sync.Mutex
	at       time.Time
	cached   []OwnAddress
	addrs    map[netip.Addr]bool
	external func() string              // the router's public address, or ""
	ifaces   func() ([]net.Addr, error) // net.InterfaceAddrs; replaced in tests
}

func newOwnAddresses(external func() string) *ownAddresses {
	return &ownAddresses{external: external, ifaces: net.InterfaceAddrs}
}

// refresh reads the addresses again when the cached ones are old. mu is held.
func (o *ownAddresses) refresh() {
	if o.addrs != nil && time.Since(o.at) < ownAddrTTL {
		return
	}
	addrs := map[netip.Addr]bool{}
	var list []OwnAddress
	add := func(a netip.Addr, source string) {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || addrs[a] {
			return
		}
		addrs[a] = true
		list = append(list, OwnAddress{IP: a.String(), Source: source})
	}
	if ifs, err := o.ifaces(); err == nil {
		for _, ia := range ifs {
			if n, ok := ia.(*net.IPNet); ok {
				if a, ok := netip.AddrFromSlice(n.IP); ok {
					add(a, "interface")
				}
			}
		}
	}
	if o.external != nil {
		if a, err := netip.ParseAddr(o.external()); err == nil {
			add(a, "router")
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Source != list[j].Source {
			return list[i].Source > list[j].Source // the router's address first
		}
		return list[i].IP < list[j].IP
	})
	o.addrs, o.cached, o.at = addrs, list, time.Now()
}

func (o *ownAddresses) has(a netip.Addr) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refresh()
	return o.addrs[a]
}

func (o *ownAddresses) list() []OwnAddress {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refresh()
	return append([]OwnAddress{}, o.cached...)
}

// OwnAddresses lists the addresses the "never ban my own addresses" setting
// covers right now.
func (e *Engine) OwnAddresses() []OwnAddress { return e.ban.own.list() }
