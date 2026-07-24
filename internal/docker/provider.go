package docker

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"quicgate/internal/store"
)

// Endpoint is one Docker daemon quicgate watches.
type Endpoint struct {
	Name    string `json:"name"`    // display name, unique
	Connect string `json:"connect"` // unix socket path, or tcp://host:port (e.g. a read-only socket proxy)
	Address string `json:"address"` // where this host's published ports are reachable from quicgate
}

// Options configures the provider.
type Options struct {
	Endpoints     []Endpoint
	LabelPrefix   string // label namespace (default quicgate)
	DefaultDomain string // optional base domain for containers without quicgate.host
}

// Hooks wires the provider to the rest of quicgate.
type Hooks struct {
	Apply           func([]store.Host, []store.Stream) // hand the derived routes to the engine
	ResolveACL      func(string) (int64, bool)         // access-list name -> id
	ExistingDomains func() map[string]bool             // database-claimed domains (manual wins)
	Setting         func(key, def string) string       // live settings lookup (default-domain)
}

// ContainerStatus is one container's integration result, surfaced in the UI so
// the reason a container is (not) routed is always visible.
type ContainerStatus struct {
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Routed   bool     `json:"routed"`
	Domains  []string `json:"domains,omitempty"`
	Upstream string   `json:"upstream,omitempty"`
	Streams  []string `json:"streams,omitempty"` // e.g. "25565/tcp -> 192.168.1.9:25565"
	Warnings []string `json:"warnings,omitempty"`
}

// EndpointStatus is one Docker host's connection state.
type EndpointStatus struct {
	Name      string `json:"name"`
	Connect   string `json:"connect"`
	Address   string `json:"address"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

// Status is the provider's live state for the admin API.
type Status struct {
	Enabled    bool              `json:"enabled"`
	Endpoints  []EndpointStatus  `json:"endpoints"`
	Containers []ContainerStatus `json:"containers"`
	UpdatedAt  string            `json:"updatedAt,omitempty"`
}

// adopted is a container's routable spec, retained so the UI can persist it as
// editable configuration with one click.
type adopted struct {
	host    *store.Host
	streams []store.Stream
}

// rawDerived is one container's derivation before cross-endpoint / database
// conflict resolution (which the aggregator does globally).
type rawDerived struct {
	name     string
	host     *store.Host
	streams  []store.Stream
	warnings []string
}

// epState is the live state of one endpoint's watch loop.
type epState struct {
	cfg      Endpoint
	cli      *Client
	labelKey string
	trigger  chan struct{}

	mu        sync.Mutex
	connected bool
	errMsg    string
	raw       []rawDerived
}

// Provider watches one or more Docker hosts and feeds derived routes to the
// engine. Each endpoint runs its own watch loop; a single aggregator merges
// every endpoint's derivations (resolving conflicts, database hosts winning)
// into one host+stream set.
type Provider struct {
	eps  []*epState
	opts Options

	apply           func([]store.Host, []store.Stream)
	resolveACL      func(string) (int64, bool)
	existingDomains func() map[string]bool
	setting         func(key, def string) string

	aggMu sync.Mutex // serializes aggregation across endpoint goroutines

	mu        sync.Mutex
	status    Status
	adoptable map[string]adopted // keyed by endpoint\x00container
}

// NewProvider builds a provider from static options and the wiring hooks.
func NewProvider(opts Options, h Hooks) *Provider {
	if opts.LabelPrefix == "" {
		opts.LabelPrefix = "quicgate"
	}
	p := &Provider{
		opts:            opts,
		apply:           h.Apply,
		resolveACL:      h.ResolveACL,
		existingDomains: h.ExistingDomains,
		setting:         h.Setting,
		adoptable:       map[string]adopted{},
	}
	labelKey := opts.LabelPrefix + ".enable"
	for _, ep := range opts.Endpoints {
		p.eps = append(p.eps, &epState{
			cfg:      ep,
			cli:      NewClient(ep.Connect),
			labelKey: labelKey,
			trigger:  make(chan struct{}, 1),
		})
	}
	p.status = Status{Enabled: true}
	return p
}

// Status returns a snapshot for the admin API.
func (p *Provider) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Trigger asks every endpoint to reconcile as soon as possible (used after a
// settings change so a new default-domain takes effect at once).
func (p *Provider) Trigger() {
	for _, ep := range p.eps {
		select {
		case ep.trigger <- struct{}{}:
		default:
		}
	}
}

// Adopt returns copies of the routable host and streams derived for a container
// on an endpoint, so the caller can persist them as editable configuration.
func (p *Provider) Adopt(endpoint, name string) (*store.Host, []store.Stream, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, ok := p.adoptable[endpoint+"\x00"+name]
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

// Run drives every endpoint until ctx is cancelled.
func (p *Provider) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, ep := range p.eps {
		wg.Add(1)
		go func(ep *epState) {
			defer wg.Done()
			p.runEndpoint(ctx, ep)
		}(ep)
	}
	wg.Wait()
}

// runEndpoint connects to one Docker host, reconciles, watches events, and
// reconnects with backoff. Last-known routes survive a daemon blip.
func (p *Provider) runEndpoint(ctx context.Context, ep *epState) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := ep.cli.Ping(ctx); err != nil {
			ep.setDown(fmt.Errorf("cannot reach docker at %s: %w", ep.cfg.Connect, err))
			p.aggregate()
			log.Printf("docker[%s]: %v (retry in %s)", ep.cfg.Name, err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = minDur(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		log.Printf("docker[%s]: connected to %s (address %s)", ep.cfg.Name, ep.cfg.Connect, ep.cfg.Address)
		p.reconcileEndpoint(ctx, ep)
		if err := p.watchEndpoint(ctx, ep); err != nil && ctx.Err() == nil {
			ep.setDown(fmt.Errorf("event stream ended: %w", err))
			p.aggregate()
			log.Printf("docker[%s]: event stream ended: %v (reconnecting)", ep.cfg.Name, err)
			sleepCtx(ctx, 2*time.Second)
		}
	}
}

// watchEndpoint streams events and reconciles on a short debounce.
func (p *Provider) watchEndpoint(ctx context.Context, ep *epState) error {
	evCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan Event, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- ep.cli.Events(evCtx, ep.labelKey, ch) }()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	pending := false
	arm := func() {
		if !pending {
			pending = true
			timer.Reset(300 * time.Millisecond)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ch:
			arm()
		case <-ep.trigger:
			arm()
		case <-timer.C:
			pending = false
			p.reconcileEndpoint(ctx, ep)
		}
	}
}

// reconcileEndpoint lists this endpoint's opted-in containers and derives each
// (raw, before conflict resolution), then triggers a global aggregation.
func (p *Provider) reconcileEndpoint(ctx context.Context, ep *epState) {
	list, err := ep.cli.List(ctx, ep.labelKey)
	if err != nil {
		ep.setDown(fmt.Errorf("list containers: %w", err))
		p.aggregate()
		return
	}
	var raw []rawDerived
	for _, sum := range list {
		in, err := ep.cli.Inspect(ctx, sum.ID)
		if err != nil {
			raw = append(raw, rawDerived{name: sum.name(), warnings: []string{"inspect failed: " + err.Error()}})
			continue
		}
		d := p.derive(in, ep.cfg.Address)
		if !d.enabled {
			continue
		}
		raw = append(raw, rawDerived{name: d.container, host: d.host, streams: d.streams, warnings: d.warnings})
	}
	ep.mu.Lock()
	ep.connected = true
	ep.errMsg = ""
	ep.raw = raw
	ep.mu.Unlock()
	p.aggregate()
}

// aggregate merges every endpoint's raw derivations into one host+stream set,
// resolving conflicts (database hosts win, then first-come across endpoints),
// applies it to the engine, and records status. Serialized so concurrent
// endpoint goroutines cannot race on the applied set.
func (p *Provider) aggregate() {
	p.aggMu.Lock()
	defer p.aggMu.Unlock()

	existing := p.existingDomains()
	claimed := map[string]bool{}
	var hosts []store.Host
	var streams []store.Stream
	var statuses []ContainerStatus
	var endpoints []EndpointStatus
	adoptable := map[string]adopted{}

	for _, ep := range p.eps {
		ep.mu.Lock()
		endpoints = append(endpoints, EndpointStatus{
			Name: ep.cfg.Name, Connect: ep.cfg.Connect, Address: ep.cfg.Address,
			Connected: ep.connected, Error: ep.errMsg,
		})
		raw := ep.raw
		ep.mu.Unlock()

		for _, rd := range raw {
			st := ContainerStatus{Name: rd.name, Endpoint: ep.cfg.Name, Warnings: rd.warnings}
			var routedHost *store.Host
			if rd.host != nil {
				var kept []string
				for _, dom := range rd.host.Domains {
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
					hc := *rd.host
					hc.Domains = kept
					hosts = append(hosts, hc)
					routedHost = &hc
					st.Routed = true
					st.Domains = kept
					st.Upstream = fmt.Sprintf("%s://%s:%d", hc.Upstream.Scheme, hc.Upstream.Host, hc.Upstream.Port)
				}
			}
			for _, s := range rd.streams {
				streams = append(streams, s)
				st.Routed = true
				st.Streams = append(st.Streams, fmt.Sprintf("%d/%s -> %s:%d", s.ListenPort, s.Protocol, s.ForwardHost, s.ForwardPort))
			}
			if routedHost != nil || len(rd.streams) > 0 {
				adoptable[ep.cfg.Name+"\x00"+rd.name] = adopted{host: routedHost, streams: rd.streams}
			}
			statuses = append(statuses, st)
		}
	}

	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].Endpoint != statuses[j].Endpoint {
			return statuses[i].Endpoint < statuses[j].Endpoint
		}
		return statuses[i].Name < statuses[j].Name
	})

	p.apply(hosts, streams)

	p.mu.Lock()
	p.status = Status{Enabled: true, Endpoints: endpoints, Containers: statuses, UpdatedAt: nowStr()}
	p.adoptable = adoptable
	p.mu.Unlock()
	log.Printf("docker: %d host(s) + %d stream(s) across %d endpoint(s)", len(hosts), len(streams), len(p.eps))
}

func (ep *epState) setDown(err error) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.connected = false
	ep.errMsg = err.Error()
	// Keep ep.raw so last-known routes survive a daemon blip.
}

func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

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
