package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// healthChecker actively probes upstream targets and tracks up/down so the
// load balancer can skip dead backends. One shared checker for all hosts.
type healthChecker struct {
	mu      sync.RWMutex
	targets map[string]*targetHealth // key: upstreamKey
	// dial connects to a target, through its WireGuard site when it has one.
	// Set by the engine; nil in tests that only probe the host network.
	dial func(via int64, network, addr string, timeout time.Duration) (net.Conn, error)
}

// healthTarget is one backend to probe.
type healthTarget struct {
	scheme, hostport string
	via              int64
	// tlsSkipVerify and tlsServerName are how the host's own traffic verifies
	// this backend's certificate; the probe verifies it the same way.
	tlsSkipVerify bool
	tlsServerName string
}

type targetHealth struct {
	up       bool
	lastErr  string
	checked  time.Time
	scheme   string
	hostport string
	via      int64
	// client makes the HTTP probe, built for this target's TLS settings.
	client        *http.Client
	tlsSkipVerify bool
	tlsServerName string
}

func newHealthChecker() *healthChecker {
	h := &healthChecker{targets: map[string]*targetHealth{}}
	go h.loop()
	return h
}

// probeClient builds the HTTP client of one target's probe. Certificates are
// verified unless the host that uses the backend skips verification for its
// own traffic: a probe that believed any certificate would let whoever sits in
// the path keep a dead or foreign backend "healthy".
func probeClient(skipVerify bool, serverName string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: skipVerify, ServerName: serverName},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// setTargets reconciles the tracked set; new targets start optimistically up.
func (h *healthChecker) setTargets(want map[string]healthTarget) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.targets {
		if _, ok := want[key]; !ok {
			delete(h.targets, key)
		}
	}
	for key, v := range want {
		t, ok := h.targets[key]
		if !ok {
			t = &targetHealth{up: true, scheme: v.scheme, hostport: v.hostport, via: v.via}
			h.targets[key] = t
		}
		if t.client == nil || t.tlsSkipVerify != v.tlsSkipVerify || t.tlsServerName != v.tlsServerName {
			t.tlsSkipVerify, t.tlsServerName = v.tlsSkipVerify, v.tlsServerName
			t.client = probeClient(v.tlsSkipVerify, v.tlsServerName)
		}
	}
}

// TargetStatus is one backend's health for the API.
type TargetStatus struct {
	Target  string `json:"target"`
	Up      bool   `json:"up"`
	LastErr string `json:"lastErr,omitempty"`
}

// HealthStatuses returns the current up/down of every tracked target.
func (e *Engine) HealthStatuses() []TargetStatus {
	e.health.mu.RLock()
	defer e.health.mu.RUnlock()
	out := make([]TargetStatus, 0, len(e.health.targets))
	for key, t := range e.health.targets {
		out = append(out, TargetStatus{Target: key, Up: t.up, LastErr: t.lastErr})
	}
	return out
}

func (h *healthChecker) up(key string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t, ok := h.targets[key]
	return !ok || t.up // unknown target: assume up
}

// markDown records that a request could not reach a target, so the balancer
// avoids it from now until the periodic probe finds it answering again. A
// target the checker does not track is left alone.
func (h *healthChecker) markDown(key string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.targets[key]
	if !ok || !t.up {
		return
	}
	t.up, t.lastErr, t.checked = false, err.Error(), time.Now()
	log.Printf("health: %s marked down after a failed connection: %v", key, err)
}

func (h *healthChecker) loop() {
	for {
		time.Sleep(15 * time.Second)
		h.mu.RLock()
		snapshot := make([]*targetHealth, 0, len(h.targets))
		clients := make([]*http.Client, 0, len(h.targets))
		for _, t := range h.targets {
			snapshot = append(snapshot, t)
			clients = append(clients, t.client)
		}
		h.mu.RUnlock()
		for i, t := range snapshot {
			up, errStr := h.probe(t.scheme, t.hostport, t.via, clients[i])
			h.mu.Lock()
			t.up, t.lastErr, t.checked = up, errStr, time.Now()
			h.mu.Unlock()
		}
	}
}

// probe does a cheap liveness check: TCP connect, then an HTTP HEAD/GET that
// counts any response (even 4xx/5xx) as "the backend is alive". A backend
// whose certificate does not verify the way the host expects is down: the
// proxy would refuse it too.
func (h *healthChecker) probe(scheme, hostport string, via int64, client *http.Client) (bool, string) {
	dial := h.dial
	if dial == nil {
		if via != 0 {
			return false, "no WireGuard endpoint to probe through"
		}
		dial = func(_ int64, network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		}
	}
	conn, err := dial(via, "tcp", hostport, 4*time.Second)
	if err != nil {
		return false, err.Error()
	}
	conn.Close()
	if via != 0 {
		// The HTTP probe below uses the host network. A backend behind a site
		// must never be contacted there, so the connect through the tunnel is
		// the whole probe.
		return true, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostport+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		if isCertError(err) {
			return false, err.Error()
		}
		// TCP was fine; treat a non-HTTP backend as alive rather than flap.
		return true, ""
	}
	resp.Body.Close()
	return true, ""
}

// isCertError reports whether a probe failed on the backend's certificate.
func isCertError(err error) bool {
	var (
		verify   *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	return errors.As(err, &verify) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

// balancer round-robins over a fixed target list, preferring healthy ones.
type balancer struct {
	targets []balTarget
	next    atomic.Uint32
	health  *healthChecker
}

type balTarget struct {
	key string // scheme://host:port plus the site: the health checker's key
	url string
	id  string   // opaque affinity id (short hash of key) for sticky sessions
	via int64    // the WireGuard site the backend is reached through; 0 is the host network
	u   *url.URL // the backend as the proxy's target
}

// targetID is the opaque cookie value identifying a backend for sticky
// sessions, a short hash so the upstream address is never exposed.
func targetID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}

// stickyPick honors the affinity cookie when it maps to a healthy backend,
// otherwise round-robins to a healthy one.
func (b *balancer) stickyPick(cookieVal string) balTarget {
	if cookieVal != "" {
		for _, t := range b.targets {
			if t.id == cookieVal && b.health.up(t.key) {
				return t
			}
		}
	}
	n := len(b.targets)
	start := b.next.Add(1)
	for i := 0; i < n; i++ {
		t := b.targets[(int(start)+i)%n]
		if b.health.up(t.key) {
			return t
		}
	}
	return b.targets[int(start)%n]
}

func (b *balancer) pick() balTarget {
	n := len(b.targets)
	if n == 1 {
		return b.targets[0]
	}
	start := b.next.Add(1)
	// First pass: first healthy target in round-robin order.
	for i := 0; i < n; i++ {
		t := b.targets[(int(start)+i)%n]
		if b.health.up(t.key) {
			return t
		}
	}
	// All down: still try one so a transient full-outage recovers.
	return b.targets[int(start)%n]
}
