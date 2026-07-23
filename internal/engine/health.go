package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// healthChecker actively probes upstream targets and tracks up/down so the
// load balancer can skip dead backends. One shared checker for all hosts.
type healthChecker struct {
	mu      sync.RWMutex
	targets map[string]*targetHealth // key: "scheme://host:port"
	client  *http.Client
}

type targetHealth struct {
	up       bool
	lastErr  string
	checked  time.Time
	scheme   string
	hostport string
}

func newHealthChecker() *healthChecker {
	h := &healthChecker{
		targets: map[string]*targetHealth{},
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	go h.loop()
	return h
}

// setTargets reconciles the tracked set; new targets start optimistically up.
func (h *healthChecker) setTargets(want map[string]struct{ scheme, hostport string }) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.targets {
		if _, ok := want[key]; !ok {
			delete(h.targets, key)
		}
	}
	for key, v := range want {
		if _, ok := h.targets[key]; !ok {
			h.targets[key] = &targetHealth{up: true, scheme: v.scheme, hostport: v.hostport}
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

func (h *healthChecker) loop() {
	for {
		time.Sleep(15 * time.Second)
		h.mu.RLock()
		snapshot := make([]*targetHealth, 0, len(h.targets))
		for _, t := range h.targets {
			snapshot = append(snapshot, t)
		}
		h.mu.RUnlock()
		for _, t := range snapshot {
			up, errStr := h.probe(t.scheme, t.hostport)
			h.mu.Lock()
			t.up, t.lastErr, t.checked = up, errStr, time.Now()
			h.mu.Unlock()
		}
	}
}

// probe does a cheap liveness check: TCP connect, then an HTTP HEAD/GET that
// counts any response (even 4xx/5xx) as "the backend is alive".
func (h *healthChecker) probe(scheme, hostport string) (bool, string) {
	conn, err := net.DialTimeout("tcp", hostport, 4*time.Second)
	if err != nil {
		return false, err.Error()
	}
	conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostport+"/", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		// TCP was fine; treat a non-HTTP backend as alive rather than flap.
		return true, ""
	}
	resp.Body.Close()
	return true, ""
}

// balancer round-robins over a fixed target list, preferring healthy ones.
type balancer struct {
	targets []balTarget
	next    atomic.Uint32
	health  *healthChecker
}

type balTarget struct {
	key      string // scheme://host:port
	url      string
	hostport string
}

func (b *balancer) pick() string {
	n := len(b.targets)
	if n == 1 {
		return b.targets[0].url
	}
	start := b.next.Add(1)
	// First pass: first healthy target in round-robin order.
	for i := 0; i < n; i++ {
		t := b.targets[(int(start)+i)%n]
		if b.health.up(t.key) {
			return t.url
		}
	}
	// All down: still try one so a transient full-outage recovers.
	return b.targets[int(start)%n].url
}
