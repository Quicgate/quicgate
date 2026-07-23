package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

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
	stop   func()
}

// Sync starts/stops forwarders so the running set matches the store.
func (m *StreamManager) Sync(streams []store.Stream) {
	desired := map[string]string{} // key -> target
	for _, s := range streams {
		if !s.Enabled {
			continue
		}
		target := fmt.Sprintf("%s:%d", s.ForwardHost, s.ForwardPort)
		protos := []string{s.Protocol}
		if s.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		for _, p := range protos {
			desired[fmt.Sprintf("%s:%d", p, s.ListenPort)] = target
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, f := range m.active {
		if desired[key] != f.target {
			f.stop()
			delete(m.active, key)
			log.Printf("stream: stopped %s -> %s", key, f.target)
		}
	}
	for key, target := range desired {
		if _, running := m.active[key]; running {
			continue
		}
		f, err := startForwarder(key, target)
		if err != nil {
			log.Printf("stream: cannot start %s -> %s: %v", key, target, err)
			continue
		}
		m.active[key] = f
		log.Printf("stream: started %s -> %s", key, target)
	}
}

func (m *StreamManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, f := range m.active {
		f.stop()
		delete(m.active, key)
	}
}

func startForwarder(key, target string) (*forwarder, error) {
	var proto string
	var port string
	if _, err := fmt.Sscanf(key, "tcp:%s", &port); err == nil {
		proto = "tcp"
	} else if _, err := fmt.Sscanf(key, "udp:%s", &port); err == nil {
		proto = "udp"
	} else {
		return nil, fmt.Errorf("bad key %q", key)
	}
	addr := ":" + port
	if proto == "tcp" {
		return startTCP(key, addr, target)
	}
	return startUDP(key, addr, target)
}

func startTCP(key, addr, target string) (*forwarder, error) {
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
			go pumpTCP(key, conn, target)
		}
	}()
	return &forwarder{key: key, target: target, stop: func() { close(done); ln.Close() }}, nil
}

func pumpTCP(key string, client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("stream %s: dial %s: %v", key, target, err)
		return
	}
	defer upstream.Close()
	go func() {
		_, _ = io.Copy(upstream, client)
		// Half-close toward the upstream so it sees EOF and can finish.
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
}

type udpSession struct {
	conn     net.Conn
	lastSeen time.Time
}

func startUDP(key, addr, target string) (*forwarder, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	var mu sync.Mutex
	sessions := map[string]*udpSession{}

	// Reap idle sessions.
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
				// Per-session return pump: upstream replies -> client.
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
						_, _ = pc.WriteTo(rbuf[:rn], clientAddr)
					}
				}(up, clientAddr, ck)
			}
			sess.lastSeen = time.Now()
			mu.Unlock()
			_, _ = sess.conn.Write(buf[:n])
		}
	}()
	return &forwarder{key: key, target: target, stop: func() {
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
