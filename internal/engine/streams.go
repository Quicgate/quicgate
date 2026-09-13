package engine

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"quicgate/internal/store"
)

const udpSessionIdle = 2 * time.Minute

// Limits that keep traffic from one listener from growing state without
// bound. When a limit is reached, new work is refused and logged (rate
// limited); established connections are not affected. Variables only so tests
// can exercise them at small sizes.
var (
	// udpMaxSessions caps concurrent client addresses per UDP listener. Each
	// session holds an upstream socket, a goroutine and a receive buffer.
	udpMaxSessions = 1024
	// tcpMaxConns caps concurrent connections per TCP listener.
	tcpMaxConns = 4096
	// streamHandshakeTimeout bounds TLS termination handshakes.
	streamHandshakeTimeout = 10 * time.Second
	// proxyHeaderTimeout bounds how long a trusted peer may take to send its
	// PROXY header.
	proxyHeaderTimeout = 5 * time.Second
)

// StreamManager reconciles running TCP/UDP forwarders against desired state.
type StreamManager struct {
	mu     sync.Mutex
	active map[string]*forwarder // key: "tcp:2222"
	status map[string]StreamStatus
}

func NewStreamManager() *StreamManager {
	return &StreamManager{active: map[string]*forwarder{}, status: map[string]StreamStatus{}}
}

// StreamStatus reports whether one listener of a stream is actually running.
// A saved stream can fail to run (a port another process holds, a missing
// certificate, a PROXY setup with no trusted peer); that is shown here rather
// than only logged.
type StreamStatus struct {
	StreamID int64    `json:"streamId"`
	Key      string   `json:"key"`   // "tcp:2222"
	State    string   `json:"state"` // running | failed
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Statuses returns the state of every desired listener, sorted by key.
func (m *StreamManager) Statuses() []StreamStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StreamStatus, 0, len(m.status))
	for _, s := range m.status {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
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
	trusted     []*net.IPNet // peers whose PROXY header is required and believed
	// Timeouts are snapshotted from the package limits when the listener is
	// built, so connection goroutines never read the shared variables.
	headerTimeout    time.Duration
	handshakeTimeout time.Duration
	tlsCert          *tls.Certificate  // set => terminate TLS
	sniRoutes        map[string]string // sni host -> "host:port" (passthrough)
	defaultDest      string            // fallback for SNI routing / plain forward
}

// streamSpec is the desired state of one forwarder.
type streamSpec struct {
	id     int64
	target string
	// Source filter: an access list evaluated with L4 semantics, or inline
	// CIDRs. filtered records that some filter is configured, so a filter
	// that yields nothing admits nobody instead of everybody.
	acl      *compiledAccess
	nets     []*net.IPNet
	filtered bool
	sig      string
	tcp      tcpOpts
	// failure, when set, means the stream cannot run safely as configured, so
	// no listener is started for it.
	failure  string
	warnings []string
}

func (sp *streamSpec) allowed(addr net.Addr) bool {
	if sp.acl != nil {
		return sp.acl.l4Allowed(addr.String())
	}
	if !sp.filtered {
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

// trustedPeer reports whether the socket peer may state a client address in a
// PROXY header.
func (sp *streamSpec) trustedPeer(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range sp.tcp.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// certLoader resolves a custom-cert id to a tls.Certificate.
type certLoader func(id int64) (tls.Certificate, bool)

// aclResolver returns the compiled access list with that id, or nil when it
// does not exist.
type aclResolver func(id int64) *compiledAccess

// Sync makes the running forwarders match the store. TCP streams may expand
// into a port range; each port becomes its own listener.
func (m *StreamManager) Sync(streams []store.Stream, loadCert certLoader, resolveACL aclResolver) {
	desired := map[string]*streamSpec{}
	for _, s := range streams {
		if !s.Enabled {
			continue
		}
		// Build the shared spec once per stream.
		spec := buildStreamSpec(s, loadCert, resolveACL)
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
				ps.target = hostPort(s.ForwardHost, fwdPort)
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
		if spec, ok := desired[key]; !ok || spec.sig != f.sig || spec.failure != "" {
			f.stop()
			delete(m.active, key)
			log.Printf("stream: stopped %s -> %s", key, f.target)
		}
	}
	for key := range m.status {
		if _, ok := desired[key]; !ok {
			delete(m.status, key)
		}
	}
	for key, spec := range desired {
		st := StreamStatus{StreamID: spec.id, Key: key, Warnings: spec.warnings}
		if spec.failure != "" {
			st.State, st.Error = "failed", spec.failure
			if prev := m.status[key]; prev.Error != spec.failure {
				log.Printf("stream: %s not started: %s", key, spec.failure)
			}
			m.status[key] = st
			continue
		}
		if _, running := m.active[key]; running {
			st.State = "running"
			m.status[key] = st
			continue
		}
		f, err := startForwarder(key, spec)
		if err != nil {
			log.Printf("stream: cannot start %s -> %s: %v", key, spec.target, err)
			st.State, st.Error = "failed", err.Error()
			m.status[key] = st
			continue
		}
		m.active[key] = f
		st.State = "running"
		m.status[key] = st
		log.Printf("stream: started %s -> %s", key, spec.target)
	}
}

func buildStreamSpec(s store.Stream, loadCert certLoader, resolveACL aclResolver) *streamSpec {
	target := hostPort(s.ForwardHost, s.ForwardPort)
	spec := &streamSpec{
		id:     s.ID,
		target: target,
		tcp: tcpOpts{
			sendProxy:        s.SendProxyProtocol,
			acceptProxy:      s.AcceptProxyProtocol,
			defaultDest:      target,
			headerTimeout:    proxyHeaderTimeout,
			handshakeTimeout: streamHandshakeTimeout,
		},
	}
	fail := func(format string, args ...any) {
		if spec.failure == "" {
			spec.failure = fmt.Sprintf(format, args...)
		}
	}

	// Source filter: an access list with L4 semantics, or the inline CIDR list.
	var srcSig string
	switch {
	case s.AccessListID != nil:
		spec.filtered = true
		var acl *compiledAccess
		if resolveACL != nil {
			acl = resolveACL(*s.AccessListID)
		}
		if acl == nil {
			fail("access list %d does not exist", *s.AccessListID)
			acl = deniedAccess(fmt.Sprintf("access list %d", *s.AccessListID))
		}
		spec.acl = acl
		spec.warnings = append(spec.warnings, acl.l4Warnings()...)
		srcSig = "acl:" + acl.fingerprint()
	case len(s.AllowedCIDRs) > 0:
		spec.filtered = true
		for _, c := range s.AllowedCIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				spec.nets = append(spec.nets, n)
			} else {
				spec.warnings = append(spec.warnings, fmt.Sprintf("source CIDR %q does not parse and is ignored", c))
			}
		}
		if len(spec.nets) == 0 {
			fail("none of the source CIDRs parse, so no client could be admitted")
		}
		srcSig = fmt.Sprintf("%v", s.AllowedCIDRs)
	}

	if s.AcceptProxyProtocol {
		for _, c := range s.TrustedProxies {
			if _, n, err := net.ParseCIDR(c); err == nil {
				spec.tcp.trusted = append(spec.tcp.trusted, n)
			}
		}
		if len(spec.tcp.trusted) == 0 {
			fail("accepting PROXY protocol needs at least one trusted proxy address")
		}
	}

	certSig := ""
	if s.TerminateTLS {
		switch {
		case s.CertID == nil:
			fail("TLS termination has no certificate")
		case loadCert == nil:
			fail("TLS certificate %d is unavailable", *s.CertID)
		default:
			if cert, ok := loadCert(*s.CertID); ok && len(cert.Certificate) > 0 {
				spec.tcp.tlsCert = &cert
				sum := sha256.Sum256(cert.Certificate[0])
				certSig = hex.EncodeToString(sum[:8])
			} else {
				fail("TLS certificate %d is unavailable", *s.CertID)
			}
		}
	}
	if len(s.SNIRoutes) > 0 {
		spec.tcp.sniRoutes = map[string]string{}
		for _, r := range s.SNIRoutes {
			spec.tcp.sniRoutes[r.Host] = hostPort(r.ForwardHost, r.ForwardPort)
		}
	}
	// The signature decides whether a running listener is replaced, so it
	// covers everything the listener was built from, including the certificate
	// contents (a replaced certificate must restart the listener).
	spec.sig = fmt.Sprintf("%s|%s|pp:%s/%v/%v|tls:%v/%v/%s|sni:%v", target, srcSig,
		s.SendProxyProtocol, s.AcceptProxyProtocol, s.TrustedProxies, s.TerminateTLS, s.CertID, certSig, s.SNIRoutes)
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

// throttledLog logs at most once per interval, for limits that attacker
// traffic can hit on every packet.
type throttledLog struct {
	mu   sync.Mutex
	last time.Time
}

func (t *throttledLog) printf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.last) < time.Minute {
		return
	}
	t.last = time.Now()
	log.Printf(format, args...)
}

func startTCP(key, addr string, spec *streamSpec) (*forwarder, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	maxConns := tcpMaxConns
	slots := make(chan struct{}, maxConns)
	var limited throttledLog
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
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					handleTCP(key, conn, spec)
				}()
			default:
				limited.printf("stream %s: %d concurrent connections reached, refusing new ones", key, maxConns)
				_ = conn.Close()
			}
		}
	}()
	return &forwarder{key: key, target: spec.target, sig: spec.sig, stop: func() { close(done); ln.Close() }}, nil
}

// handleTCP applies PROXY-accept, SNI routing or TLS termination as
// configured, then splices the connection to the chosen backend.
func handleTCP(key string, raw net.Conn, spec *streamSpec) {
	defer raw.Close()
	var clientConn net.Conn = raw
	clientAddr := raw.RemoteAddr()

	// Only a trusted peer may state the client address, and it must: a load
	// balancer that is trusted always sends the header, so a missing, malformed
	// or slow one closes the connection. Any other peer is a direct client, its
	// socket address is its identity, and nothing it sends is read as a header.
	if spec.tcp.acceptProxy && spec.trustedPeer(raw.RemoteAddr()) {
		pc := proxyproto.NewConn(raw, proxyproto.WithPolicy(proxyproto.REQUIRE), proxyproto.SetReadHeaderTimeout(spec.tcp.headerTimeout))
		if pc.ProxyHeader() == nil {
			log.Printf("stream %s: trusted peer %s sent no valid PROXY header", key, raw.RemoteAddr())
			return
		}
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
		_ = clientConn.SetDeadline(time.Now().Add(spec.tcp.handshakeTimeout))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("stream %s: TLS handshake failed: %v", key, err)
			return
		}
		_ = clientConn.SetDeadline(time.Time{})
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
	maxSessions := udpMaxSessions
	var limited throttledLog

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
				if len(sessions) >= maxSessions {
					mu.Unlock()
					limited.printf("stream %s: %d concurrent UDP sessions reached, dropping packets from new sources", key, maxSessions)
					continue
				}
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

// fingerprint summarises everything that decides a compiled list's verdicts, so
// a stream listener is only rebuilt when its filter really changed (a periodic
// reload recompiles every list into new objects with the same content).
func (c *compiledAccess) fingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|r%v|d%v|u%d|", c.name, c.satisfy, c.restricted, c.denyAll, len(c.users))
	for _, r := range c.rules {
		fmt.Fprintf(&b, "%v/%v/%s/%v/%v;", r.allow, r.net, r.country, r.unresolved, r.methods)
	}
	return b.String()
}
