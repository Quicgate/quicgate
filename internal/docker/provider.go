package docker

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"quicgate/internal/store"
)

// Options configures the provider. Zero values fall back to sane defaults.
type Options struct {
	Socket        string // path to the Docker socket (default /var/run/docker.sock)
	ConnectMode   string // auto | network | published (default auto)
	HostAddress   string // where published/host-net ports are reachable (default 127.0.0.1)
	DefaultDomain string // optional base domain for containers without quicgate.host
	LabelPrefix   string // label namespace (default quicgate)
	SelfContainer string // quicgate's own container name/id, for network-mode detection
}

// ContainerStatus is one container's integration result, surfaced in the UI so
// the reason a container is (not) routed is always visible.
type ContainerStatus struct {
	Name     string   `json:"name"`
	Routed   bool     `json:"routed"`
	Domains  []string `json:"domains,omitempty"`
	Upstream string   `json:"upstream,omitempty"`
	Streams  []string `json:"streams,omitempty"` // e.g. "25565/tcp -> 127.0.0.1:25565"
	Mode     string   `json:"mode,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Status is the provider's live state for the admin API.
type Status struct {
	Enabled     bool              `json:"enabled"`
	Connected   bool              `json:"connected"`
	Socket      string            `json:"socket"`
	ConnectMode string            `json:"connectMode"`
	Error       string            `json:"error,omitempty"`
	Containers  []ContainerStatus `json:"containers"`
	UpdatedAt   string            `json:"updatedAt,omitempty"`
}

// Hooks wires the provider to the rest of quicgate.
type Hooks struct {
	Apply           func([]store.Host, []store.Stream) // hand the derived routes to the engine
	ResolveACL      func(string) (int64, bool)         // access-list name -> id
	ExistingDomains func() map[string]bool             // database-claimed domains (manual wins)
	Setting         func(key, def string) string       // live settings lookup (connect-mode etc.)
}

// Provider watches Docker and feeds derived hosts to the engine.
type Provider struct {
	cli      *Client
	opts     Options
	labelKey string

	apply           func([]store.Host, []store.Stream)
	resolveACL      func(string) (int64, bool)
	existingDomains func() map[string]bool
	setting         func(key, def string) string

	selfNets map[string]bool // networks quicgate itself is on (empty on host-net)
	trigger  chan struct{}   // pokes the watch loop to reconcile now

	mu        sync.Mutex
	status    Status
	adoptable map[string]adopted // per-container routable spec, for convert-to-managed
}

// adopted is a container's routable spec, retained so the UI can persist it as
// an editable host (and streams) with one click.
type adopted struct {
	host    *store.Host
	streams []store.Stream
}

// NewProvider builds a provider from static options and the wiring hooks.
func NewProvider(opts Options, h Hooks) *Provider {
	if opts.Socket == "" {
		opts.Socket = "/var/run/docker.sock"
	}
	if opts.ConnectMode == "" {
		opts.ConnectMode = "auto"
	}
	if opts.LabelPrefix == "" {
		opts.LabelPrefix = "quicgate"
	}
	p := &Provider{
		cli:             NewClient(opts.Socket),
		opts:            opts,
		labelKey:        opts.LabelPrefix + ".enable",
		apply:           h.Apply,
		resolveACL:      h.ResolveACL,
		existingDomains: h.ExistingDomains,
		setting:         h.Setting,
		trigger:         make(chan struct{}, 1),
		adoptable:       map[string]adopted{},
	}
	p.status = Status{Enabled: true, Socket: opts.Socket, ConnectMode: opts.ConnectMode}
	return p
}

// Status returns a snapshot for the admin API.
func (p *Provider) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Trigger asks the watch loop to reconcile as soon as possible (used after a
// settings change so a new connect-mode or default-domain takes effect at once).
func (p *Provider) Trigger() {
	select {
	case p.trigger <- struct{}{}:
	default:
	}
}

// Adopt returns copies of the routable host and streams derived for a
// container, so the caller can persist them as editable configuration. Once
// persisted, the manual-wins conflict rule makes the provider drop its derived
// version on the next reconcile, so nothing is served twice.
func (p *Provider) Adopt(name string) (*store.Host, []store.Stream, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, ok := p.adoptable[name]
	if !ok {
		return nil, nil, false
	}
	var h *store.Host
	if a.host != nil {
		c := *a.host
		c.Domains = append([]string(nil), a.host.Domains...)
		h = &c
	}
	return h, append([]store.Stream(nil), a.streams...), true
}

// Run drives the provider until ctx is cancelled: connect, reconcile, watch
// events, and reconnect with backoff. Last-known routes are kept across daemon
// blips so a restart of the Docker daemon does not drop everyone's traffic.
func (p *Provider) Run(ctx context.Context) {
	p.selfNets = detectSelfNetworks(ctx, p.cli, p.opts.SelfContainer)
	if len(p.selfNets) > 0 {
		log.Printf("docker: quicgate is on networks %v; network connect-mode available", mapKeys(p.selfNets))
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if err := p.cli.Ping(ctx); err != nil {
			p.setError(fmt.Errorf("cannot reach docker at %s: %w", p.opts.Socket, err))
			log.Printf("docker: %v (retry in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = minDur(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		log.Printf("docker: connected to %s (connect-mode %s, label prefix %s)", p.opts.Socket, p.opts.ConnectMode, p.labelPrefix())
		p.reconcile(ctx)
		if err := p.watch(ctx); err != nil && ctx.Err() == nil {
			p.setError(fmt.Errorf("event stream ended: %w", err))
			log.Printf("docker: event stream ended: %v (reconnecting)", err)
			sleepCtx(ctx, 2*time.Second)
		}
	}
}

// watch streams events and reconciles on a short debounce so a compose up that
// fires a burst of events collapses into a single rebuild.
func (p *Provider) watch(ctx context.Context) error {
	evCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan Event, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- p.cli.Events(evCtx, p.labelKey, ch) }()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	pending := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ch:
			if !pending {
				pending = true
				timer.Reset(300 * time.Millisecond)
			}
		case <-p.trigger:
			if !pending {
				pending = true
				timer.Reset(300 * time.Millisecond)
			}
		case <-timer.C:
			pending = false
			p.reconcile(ctx)
		}
	}
}

// reconcile lists opted-in containers, derives a host for each, resolves naming
// conflicts (database hosts win, then first-come among containers), applies the
// resulting host set to the engine, and records status. On a list error it
// keeps the last-known routes rather than dropping them.
func (p *Provider) reconcile(ctx context.Context) {
	list, err := p.cli.List(ctx, p.labelKey)
	if err != nil {
		p.setError(fmt.Errorf("list containers: %w", err))
		return
	}
	existing := p.existingDomains()
	claimed := map[string]bool{}
	var hosts []store.Host
	var streams []store.Stream
	var statuses []ContainerStatus
	adoptable := map[string]adopted{}

	for _, sum := range list {
		in, err := p.cli.Inspect(ctx, sum.ID)
		if err != nil {
			statuses = append(statuses, ContainerStatus{Name: sum.name(), Warnings: []string{"inspect failed: " + err.Error()}})
			continue
		}
		d := p.derive(in)
		if !d.enabled {
			continue
		}
		st := ContainerStatus{Name: d.container, Mode: d.mode, Warnings: d.warnings}
		var routedHost *store.Host
		if d.host != nil {
			var kept []string
			for _, dom := range d.host.Domains {
				switch {
				case existing[dom]:
					st.Warnings = append(st.Warnings, dom+" is already served by a manual host (skipped)")
				case claimed[dom]:
					st.Warnings = append(st.Warnings, dom+" is already claimed by another container (skipped)")
				default:
					claimed[dom] = true
					kept = append(kept, dom)
				}
			}
			if len(kept) > 0 {
				d.host.Domains = kept
				hosts = append(hosts, *d.host)
				routedHost = d.host
				st.Routed = true
				st.Domains = kept
				st.Upstream = fmt.Sprintf("%s://%s:%d", d.host.Upstream.Scheme, d.host.Upstream.Host, d.host.Upstream.Port)
			}
		}
		for _, s := range d.streams {
			streams = append(streams, s)
			st.Routed = true
			st.Streams = append(st.Streams, fmt.Sprintf("%d/%s -> %s:%d", s.ListenPort, s.Protocol, s.ForwardHost, s.ForwardPort))
		}
		if routedHost != nil || len(d.streams) > 0 {
			adoptable[d.container] = adopted{host: routedHost, streams: d.streams}
		}
		statuses = append(statuses, st)
	}

	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	p.apply(hosts, streams)

	p.mu.Lock()
	p.status.Connected = true
	p.status.ConnectMode = p.connectMode()
	p.status.Error = ""
	p.status.Containers = statuses
	p.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	p.adoptable = adoptable
	p.mu.Unlock()
	log.Printf("docker: reconciled %d container(s), %d host(s) + %d stream(s) routed", len(list), len(hosts), len(streams))
}

func (p *Provider) setError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status.Connected = false
	p.status.Error = err.Error()
	p.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

// detectSelfNetworks best-effort discovers the networks quicgate itself is
// attached to, so auto connect-mode can reach sibling containers by IP. On a
// host-networked quicgate the hostname is not a container id, inspect fails,
// and this returns nil, which correctly routes it down the published path.
func detectSelfNetworks(ctx context.Context, cli *Client, self string) map[string]bool {
	id := self
	if id == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return nil
		}
		id = h
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	in, err := cli.Inspect(ctx, id)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for name := range in.NetworkSettings.Networks {
		out[name] = true
	}
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
