package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"quicgate/internal/store"
)

// Options configures the provider.
type Options struct {
	Endpoints     []Endpoint
	LabelPrefix   string // label namespace (default quicgate)
	DefaultDomain string // optional base domain for containers without quicgate.host
}

// Hooks wires the provider to the rest of quicgate.
type Hooks struct {
	Apply      func([]store.Host, []store.Stream) // hand the derived routes to the engine
	ResolveACL func(string) (int64, bool)         // access-list name -> id
	// ExistingDomains lists the domains the database's hosts are configured
	// with, enabled or not and wildcards as "*.example.com": a manual host
	// wins every name conflict with a container, and a name stays taken while
	// its host is switched off.
	ExistingDomains func() map[string]bool
	// UsedPorts lists the listen ports a container's stream may not take: the
	// database streams' ports and the ports quicgate itself listens on. The
	// engine drops such a stream anyway; knowing it here lets the container's
	// status say so instead of claiming the stream is routed.
	UsedPorts func() map[int]bool
	Setting   func(key, def string) string // live settings lookup (default-domain)
}

// reaggregateEvery is how often the routes are aggregated again without a
// container event. The other side of a name conflict is the database: a
// manual host that is created takes its name from a container, one that is
// deleted gives it back, and neither raises a Docker event.
const reaggregateEvery = 30 * time.Second

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
	usedPorts       func() map[int]bool
	setting         func(key, def string) string
	reaggregate     time.Duration // period of the timer-driven aggregation (reaggregateEvery unless a test shortens it)

	aggMu   sync.Mutex // serializes aggregation across endpoint goroutines
	lastSig string     // the applied set, so an unchanged aggregation does not reload the engine

	mu        sync.Mutex
	status    Status
	adoptable map[string]adopted // keyed by endpoint\x00container
}

// NewProvider builds a provider from static options and the wiring hooks. An
// endpoint whose client cannot be built (a certificate file that does not
// open) is kept, shown with its error, and retried by its watch loop.
func NewProvider(opts Options, h Hooks) *Provider {
	if opts.LabelPrefix == "" {
		opts.LabelPrefix = "quicgate"
	}
	p := &Provider{
		opts:            opts,
		apply:           h.Apply,
		resolveACL:      h.ResolveACL,
		existingDomains: h.ExistingDomains,
		usedPorts:       h.UsedPorts,
		setting:         h.Setting,
		reaggregate:     reaggregateEvery,
		adoptable:       map[string]adopted{},
	}
	labelKey := opts.LabelPrefix + ".enable"
	for _, ep := range opts.Endpoints {
		st := &epState{cfg: ep, labelKey: labelKey, trigger: make(chan struct{}, 1)}
		cli, err := NewClient(ep)
		if err != nil {
			st.errMsg = err.Error()
			log.Printf("docker[%s]: %v", ep.Name, err)
		}
		st.cli = cli
		p.eps = append(p.eps, st)
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

// Run drives every endpoint until ctx is cancelled, and aggregates again on a
// timer in between container events.
func (p *Provider) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runPeriodic(ctx)
	}()
	for _, ep := range p.eps {
		wg.Add(1)
		go func(ep *epState) {
			defer wg.Done()
			p.runEndpoint(ctx, ep)
		}(ep)
	}
	wg.Wait()
}

// runPeriodic aggregates the last derivations again every period, so a manual
// host created or deleted in the meantime takes or frees its name without
// waiting for a container event. Aggregation reads what the endpoints already
// derived: no Docker API call is made, and the engine is only reloaded when
// the resulting set differs from the one it has.
func (p *Provider) runPeriodic(ctx context.Context) {
	t := time.NewTicker(p.reaggregate)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.aggregate()
		}
	}
}

// runEndpoint connects to one Docker host, reconciles, watches events, and
// reconnects with backoff. Last-known routes survive a daemon blip.
func (p *Provider) runEndpoint(ctx context.Context, ep *epState) {
	backoff := time.Second
	for ctx.Err() == nil {
		if ep.cli == nil {
			// The client could not be built at startup (a certificate file
			// that did not open); try again, the file may be there now.
			cli, err := NewClient(ep.cfg)
			if err != nil {
				ep.setDown(err)
				p.aggregate()
				if !sleepCtx(ctx, backoff) {
					return
				}
				backoff = minDur(backoff*2, 30*time.Second)
				continue
			}
			ep.cli = cli
		}
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

// coveringWildcard returns the wildcard name that covers an exact name the
// way the routing table matches ("*.example.com" for "api.example.com"), or
// "" for a wildcard or a single label.
func coveringWildcard(dom string) string {
	if strings.HasPrefix(dom, "*.") {
		return ""
	}
	if i := strings.IndexByte(dom, '.'); i > 0 {
		return "*." + dom[i+1:]
	}
	return ""
}

// aggregate merges every endpoint's raw derivations into one host+stream set,
// resolving conflicts (database hosts and streams win, then first-come across
// endpoints), applies it to the engine when it changed, and records status.
// Serialized so concurrent endpoint goroutines cannot race on the applied set.
func (p *Provider) aggregate() {
	p.aggMu.Lock()
	defer p.aggMu.Unlock()

	var existing map[string]bool
	if p.existingDomains != nil {
		existing = p.existingDomains()
	}
	var used map[int]bool
	if p.usedPorts != nil {
		used = p.usedPorts()
	}
	claimed := map[string]bool{}
	takenPorts := map[int]string{} // listen port -> the container that has it
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
					switch w := coveringWildcard(dom); {
					case existing[dom]:
						st.Warnings = append(st.Warnings, dom+" is configured on a manual host (skipped)")
					case w != "" && existing[w]:
						st.Warnings = append(st.Warnings, dom+" is covered by the manual wildcard host "+w+" (skipped)")
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
			var keptStreams []store.Stream
			for _, s := range rd.streams {
				who := ep.cfg.Name + "/" + rd.name
				switch {
				case used[s.ListenPort]:
					st.Warnings = append(st.Warnings, fmt.Sprintf("stream %d/%s: listen port %d belongs to a manual stream or to quicgate itself (skipped)", s.ListenPort, s.Protocol, s.ListenPort))
				case takenPorts[s.ListenPort] != "":
					st.Warnings = append(st.Warnings, fmt.Sprintf("stream %d/%s: listen port %d is already claimed by container %s (skipped)", s.ListenPort, s.Protocol, s.ListenPort, takenPorts[s.ListenPort]))
				default:
					takenPorts[s.ListenPort] = who
					keptStreams = append(keptStreams, s)
					streams = append(streams, s)
					st.Routed = true
					st.Streams = append(st.Streams, fmt.Sprintf("%d/%s -> %s:%d", s.ListenPort, s.Protocol, s.ForwardHost, s.ForwardPort))
				}
			}
			if routedHost != nil || len(keptStreams) > 0 {
				adoptable[ep.cfg.Name+"\x00"+rd.name] = adopted{host: routedHost, streams: keptStreams}
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

	p.mu.Lock()
	p.status = Status{Enabled: true, Endpoints: endpoints, Containers: statuses, UpdatedAt: nowStr()}
	p.adoptable = adoptable
	p.mu.Unlock()

	// The engine reloads on every apply, so hand it the set only when it is
	// not the one it already has; the timer-driven aggregation would otherwise
	// reload it twice a minute for nothing.
	if sig := routeSignature(hosts, streams); sig != p.lastSig {
		p.lastSig = sig
		p.apply(hosts, streams)
		log.Printf("docker: %d host(s) + %d stream(s) across %d endpoint(s)", len(hosts), len(streams), len(p.eps))
	}
}

// routeSignature is a stable rendering of an applied set (pointers by value),
// so two aggregations of the same derivations compare equal.
func routeSignature(hosts []store.Host, streams []store.Stream) string {
	h, _ := json.Marshal(hosts)
	s, _ := json.Marshal(streams)
	return string(h) + "\n" + string(s)
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
