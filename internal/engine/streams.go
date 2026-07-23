package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"quicgate/internal/store"
)

const udpSessionIdle = 2 * time.Minute

// StreamManager reconciles running TCP/UDP forwarders against desired state.
type StreamManager struct {
	mu     sync.Mutex
	active map[string]*forwarder // key: "tcp:2222"
}

func NewStreamManager() *StreamManager {
	return &StreamManager{active: map[string]*forwarder{}}
}

type forwarder struct {
	key    string
	target string
	sig    string
	stop   func()
}

// tcpOpts carries the round-2 TCP behaviors for one listener.
type tcpOpts struct {
	sendProxy   string // "" | v1 | v2
	acceptProxy bool
	tlsCert     *tls.Certificate    // set => terminate TLS
	sniRoutes   map[string]string   // sni host -> "host:port" (passthrough)
	defaultDest string              // fallback for SNI routing / plain forward
}

// streamSpec is the desired state of one forwarder.
type streamSpec struct {
	target string
	nets   []*net.IPNet
	sig    string
	tcp    tcpOpts
}

func (sp *streamSpec) allowed(addr net.Addr) bool {
	if len(sp.nets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range sp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// certLoader resolves a custom-cert id to a tls.Certificate.
type certLoader func(id int64) (tls.Certificate, bool)

// Sync makes the running forwarders match the store. TCP streams may expand
// into a port range; each port becomes its own listener.
func (m *StreamManager) Sync(streams []store.Stream, loadCert certLoader) {
	desired := map[string]*streamSpec{}
	for _, s := range streams {
		if !s.Enabled {
			continue
		}
		// Build the shared spec once per stream.
		spec := buildStreamSpec(s, loadCert)
		protos := []string{s.Protocol}
		if s.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		last := s.ListenPort
		if s.ListenPortEnd > 0 {
			last = s.ListenPortEnd
		}
		for port := s.ListenPort; port <= last; port++ {
			// For ranges, forward to forwardPort+offset, or same port if unset.
			portSpec := spec
			if last != s.ListenPort {
				fwdPort := s.ForwardPort
				if fwdPort == 0 {
					fwdPort = port
				} else {
					fwdPort = s.ForwardPort + (port - s.ListenPort)
				}
				ps := *spec
				ps.target = fmt.Sprintf("%s:%d", s.ForwardHost, fwdPort)
				ps.tcp.defaultDest = ps.target
				ps.sig = spec.sig + fmt.Sprintf("|p%d", port)
				portSpec = &ps
			}
			for _, p := range protos {
				desired[fmt.Sprintf("%s:%d", p, port)] = portSpec
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, f := range m.active {
		if spec, ok := desired[key]; !ok || spec.sig != f.sig {
			f.stop()
			delete(m.active, key)
			log.Printf("stream: stopped %s -> %s", key, f.target)
		}
	}
	for key, spec := range desired {
		if _, running := m.active[key]; running {
			continue
		}
		f, err := startForwarder(key, spec)
		if err != nil {
			log.Printf("stream: cannot start %s -> %s: %v", key, spec.target, err)
			continue
		}
		m.active[key] = f
		log.Printf("stream: started %s -> %s", key, spec.target)
	}
}

func buildStreamSpec(s store.Stream, loadCert certLoader) *streamSpec {
	target := fmt.Sprintf("%s:%d", s.ForwardHost, s.ForwardPort)
	spec := &streamSpec{
		target: target,
		sig: fmt.Sprintf("%s|%v|pp:%s/%v|tls:%v/%v|sni:%v", target, s.AllowedCIDRs,
			s.SendProxyProtocol, s.AcceptProxyProtocol, s.TerminateTLS, s.CertID, s.SNIRoutes),
		tcp: tcpOpts{
			sendProxy:   s.SendProxyProtocol,
			acceptProxy: s.AcceptProxyProtocol,
			defaultDest: target,
		},
	}
	for _, c := range s.AllowedCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			spec.nets = append(spec.nets, n)
		}
	}
	if s.TerminateTLS && s.CertID != nil && loadCert != nil {
		if cert, ok := loadCert(*s.CertID); ok {
			spec.tcp.tlsCert = &cert
		} else {
			log.Printf("stream :%d: TLS cert %d unavailable, termination disabled", s.ListenPort, *s.CertID)
		}
	}
	if len(s.SNIRoutes) > 0 {
		spec.tcp.sniRoutes = map[string]string{}
		for _, r := range s.SNIRoutes {
			spec.tcp.sniRoutes[r.Host] = fmt.Sprintf("%s:%d", r.ForwardHost, r.ForwardPort)
		}
	}
	return spec
}

func (m *StreamManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, f := range m.active {
		f.stop()
		delete(m.active, key)
	}
}

func startForwarder(key string, spec *streamSpec) (*forwarder, error) {
	var proto, port string
	if _, err := fmt.Sscanf(key, "tcp:%s", &port); err == nil {
		proto = "tcp"
	} else if _, err := fmt.Sscanf(key, "udp:%s", &port); err == nil {
		proto = "udp"
	} else {
		return nil, fmt.Errorf("bad key %q", key)
	}
	addr := ":" + port
	if proto == "tcp" {
		return startTCP(key, addr, spec)
	}
	return startUDP(key, addr, spec)
}

func startTCP(key, addr string, spec *streamSpec) (*forwarder, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					log.Printf("stream %s: accept: %v", key, err)
					return
				}
			}
			go handleTCP(key, conn, spec)
		}
	}()
	return &forwarder{key: key, target: spec.target, sig: spec.sig, stop: func() { close(done); ln.Close() }}, nil
}

// handleTCP applies PROXY-accept, SNI routing or TLS termination as
// configured, then splices the connection to the chosen backend.
func handleTCP(key string, raw net.Conn, spec *streamSpec) {
	defer raw.Close()
	clientConn := raw
	clientAddr := raw.RemoteAddr()

	// Accept an inbound PROXY header (real client behind another proxy).
	if spec.tcp.acceptProxy {
		pc := proxyproto.NewConn(raw)
		clientConn = pc
		clientAddr = pc.RemoteAddr()
	}

	// Whitelist against the effective client address.
	if !spec.allowed(clientAddr) {
		log.Printf("stream %s: refused %s (not in whitelist)", key, clientAddr)
		return
	}

	var upstreamReader io.Reader = clientConn
	dest := spec.tcp.defaultDest

	switch {
	case spec.tcp.sniRoutes != nil:
		// TLS passthrough: peek the SNI, route, forward original bytes.
		sni, peeked, err := peekSNI(clientConn)
		if err != nil {
			log.Printf("stream %s: SNI peek failed: %v", key, err)
			return
		}
		if d, ok := spec.tcp.sniRoutes[sni]; ok {
			dest = d
		}
		upstreamReader = io.MultiReader(peeked, clientConn)

	case spec.tcp.tlsCert != nil:
		// Terminate TLS here, forward plaintext to the backend.
		tlsConn := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*spec.tcp.tlsCert}})
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("stream %s: TLS handshake failed: %v", key, err)
			return
		}
		clientConn = tlsConn
		upstreamReader = tlsConn
	}

	backend, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		log.Printf("stream %s: dial %s: %v", key, dest, err)
		return
	}
	defer backend.Close()

	// Announce the real client to the backend via PROXY protocol.
	if spec.tcp.sendProxy != "" {
		v := byte(1)
		if spec.tcp.sendProxy == "v2" {
			v = 2
		}
		h := proxyproto.HeaderProxyFromAddrs(v, clientAddr, backend.RemoteAddr())
		if _, err := h.WriteTo(backend); err != nil {
			log.Printf("stream %s: write PROXY header: %v", key, err)
			return
		}
	}

	go func() {
		io.Copy(backend, upstreamReader)
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	io.Copy(clientConn, backend)
}

func startUDP(key, addr string, spec *streamSpec) (*forwarder, error) {
	target := spec.target
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	var mu sync.Mutex
	sessions := map[string]*udpSession{}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.lastSeen) > udpSessionIdle {
						s.conn.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
				default:
					log.Printf("stream %s: read: %v", key, err)
				}
				return
			}
			if !spec.allowed(clientAddr) {
				continue
			}
			ck := clientAddr.String()
			mu.Lock()
			sess, ok := sessions[ck]
			if !ok {
				up, err := net.DialTimeout("udp", target, 5*time.Second)
				if err != nil {
					mu.Unlock()
					log.Printf("stream %s: dial %s: %v", key, target, err)
					continue
				}
				sess = &udpSession{conn: up, lastSeen: time.Now()}
				sessions[ck] = sess
				go func(up net.Conn, clientAddr net.Addr, ck string) {
					rbuf := make([]byte, 65535)
					for {
						up.SetReadDeadline(time.Now().Add(udpSessionIdle))
						rn, err := up.Read(rbuf)
						if err != nil {
							mu.Lock()
							if s, ok := sessions[ck]; ok && s.conn == up {
								delete(sessions, ck)
							}
							mu.Unlock()
							up.Close()
							return
						}
						pc.WriteTo(rbuf[:rn], clientAddr)
					}
				}(up, clientAddr, ck)
			}
			sess.lastSeen = time.Now()
			mu.Unlock()
			sess.conn.Write(buf[:n])
		}
	}()
	return &forwarder{key: key, target: target, sig: spec.sig, stop: func() {
		close(done)
		pc.Close()
		mu.Lock()
		for k, s := range sessions {
			s.conn.Close()
			delete(sessions, k)
		}
		mu.Unlock()
	}}, nil
}

type udpSession struct {
	conn     net.Conn
	lastSeen time.Time
}
