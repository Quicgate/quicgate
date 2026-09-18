package wg

// The glue between wireguard-go and the gVisor network stack. It follows
// golang.zx2c4.com/wireguard/tun/netstack (MIT, Copyright (C) 2017-2025
// WireGuard LLC), reduced to IPv4 and with the stack itself exposed, because
// forwarding for devices (forward.go) needs a promiscuous interface and
// transport-level forwarders, which that package does not offer.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID = 1
	// Bounds on what the stack may hold before any policy is asked (S49). The
	// link queue and the socket buffers are per stack and per connection.
	linkQueueLen  = 512
	tcpBufDefault = 128 << 10
	tcpBufMax     = 512 << 10
)

// netStack is one userspace IPv4 stack behind one WireGuard device. It
// implements tun.Device for wireguard-go.
type netStack struct {
	ep       *channel.Endpoint
	s        *stack.Stack
	addr     netip.Addr
	mtu      int
	events   chan tun.Event
	incoming chan *buffer.View
	notify   *channel.NotificationHandle
	done     chan struct{}
	once     sync.Once
}

func newNetStack(addr netip.Addr, mtu int) (*netStack, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("the tunnel address must be IPv4")
	}
	n := &netStack{
		ep:       channel.New(linkQueueLen, uint32(mtu), ""),
		addr:     addr,
		mtu:      mtu,
		events:   make(chan tun.Event, 4),
		incoming: make(chan *buffer.View),
		done:     make(chan struct{}),
	}
	n.s = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		// HandleLocal stays off, unlike in wireguard-go's own glue. With it on,
		// gVisor drops every packet whose source is "one of our addresses", and
		// on a promiscuous interface every address is: the forwarder would see
		// nothing. quicgate never talks to itself through this stack.
		HandleLocal: false,
	})
	sack := tcpip.TCPSACKEnabled(true)
	if err := n.s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("tcp sack: %v", err)
	}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: tcpBufDefault, Max: tcpBufMax}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: tcpBufDefault, Max: tcpBufMax}
	if err := n.s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		return nil, fmt.Errorf("tcp receive buffer: %v", err)
	}
	if err := n.s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		return nil, fmt.Errorf("tcp send buffer: %v", err)
	}
	n.notify = n.ep.AddNotify(n)
	if err := n.s.CreateNIC(nicID, n.ep); err != nil {
		return nil, fmt.Errorf("create interface: %v", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := n.s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %v", err)
	}
	n.s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	n.events <- tun.EventUp
	return n, nil
}

// promiscuous lets the interface take packets for any destination and answer
// from addresses that are not its own. Only the forwarder needs it.
func (n *netStack) promiscuous() error {
	if err := n.s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("promiscuous mode: %v", err)
	}
	if err := n.s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("spoofing: %v", err)
	}
	return nil
}

// tun.Device

func (n *netStack) Name() (string, error)    { return "quicgate", nil }
func (n *netStack) File() *os.File           { return nil }
func (n *netStack) Events() <-chan tun.Event { return n.events }
func (n *netStack) MTU() (int, error)        { return n.mtu, nil }
func (n *netStack) BatchSize() int           { return 1 }

// Read hands wireguard-go the next packet the stack wants to send.
func (n *netStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case view := <-n.incoming:
		c, err := view.Read(bufs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = c
		return 1, nil
	case <-n.done:
		return 0, os.ErrClosed
	}
}

// Write gives the stack the packets wireguard-go decrypted. wireguard-go has
// already checked their source against the sending peer's allowed addresses.
func (n *netStack) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		packet := b[offset:]
		if len(packet) == 0 || packet[0]>>4 != 4 {
			continue // IPv4 only
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	}
	return len(bufs), nil
}

// WriteNotify is called by the link endpoint when the stack has a packet.
func (n *netStack) WriteNotify() {
	pkt := n.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case n.incoming <- view:
	case <-n.done:
	}
}

func (n *netStack) Close() error {
	n.once.Do(func() {
		close(n.done)
		n.s.RemoveNIC(nicID)
		n.s.Close()
		n.ep.RemoveNotify(n.notify)
		n.ep.Close()
		close(n.events)
	})
	return nil
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}

func (n *netStack) dialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, n.s, fullAddr(to), ipv4.ProtocolNumber)
}

func (n *netStack) dialUDP(to netip.AddrPort) (net.Conn, error) {
	ra := fullAddr(to)
	return gonet.DialUDP(n.s, nil, &ra, ipv4.ProtocolNumber)
}

// listenTCP listens on the stack's own address only.
func (n *netStack) listenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(n.s, fullAddr(netip.AddrPortFrom(n.addr, port)), ipv4.ProtocolNumber)
}

func (n *netStack) listenUDP(port uint16) (net.PacketConn, error) {
	la := fullAddr(netip.AddrPortFrom(n.addr, port))
	return gonet.DialUDP(n.s, &la, nil, ipv4.ProtocolNumber)
}
