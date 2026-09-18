package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// WireGuard sites (SPEC-wireguard.md, part 1). An upstream or a stream target
// that names a site (store.Upstream.Via, store.Stream.Via) is reached through
// the embedded WireGuard endpoint. Every dial to a target goes through
// dialTarget, which is the only place that decides between the host network
// and the tunnel, and it decides by the site alone, never by the address: a
// target with a site is never dialled on the host network, whatever happens
// to the tunnel (S6, S8).

const (
	wgDefaultPort    = 51820
	wgDefaultNetwork = "10.77.0.0/24"
)

// wgState is what the last reload made of the WireGuard settings.
type wgState struct {
	enabled   bool
	err       string // why the endpoint is not running although it is enabled
	publicKey string
	port      int
	network   netip.Prefix
	endpoint  string
}

// WGStatus is the state of the endpoint for the admin API.
type WGStatus struct {
	Enabled   bool            `json:"enabled"`
	Running   bool            `json:"running"`
	Error     string          `json:"error,omitempty"`
	PublicKey string          `json:"publicKey,omitempty"`
	Port      int             `json:"port"`
	Network   string          `json:"network"`
	Address   string          `json:"address"` // quicgate's own address in the tunnel
	Endpoint  string          `json:"endpoint"`
	Resets    uint64          `json:"resets"`
	Sites     []wg.SiteStatus `json:"sites"`
}

// WGSettings reads the WireGuard settings with their defaults.
func WGSettings(st *store.Store) (port int, network netip.Prefix, endpoint string, err error) {
	port = wgDefaultPort
	if v := st.GetSetting("wg_port", ""); v != "" {
		p, perr := strconv.Atoi(v)
		if perr != nil || p < 1 || p > 65535 {
			return 0, netip.Prefix{}, "", fmt.Errorf("wg_port %q is not a port", v)
		}
		port = p
	}
	network, err = netip.ParsePrefix(st.GetSetting("wg_network", wgDefaultNetwork))
	if err != nil || !network.Addr().Is4() || network.Bits() < 16 || network.Bits() > 29 {
		return 0, netip.Prefix{}, "", fmt.Errorf("wg_network must be an IPv4 prefix between /16 and /29")
	}
	return port, network.Masked(), st.GetSetting("wg_endpoint", ""), nil
}

// wgSite converts a stored site. ok is false for a site that cannot be
// configured (a preshared key the locked store cannot open, a bad address).
func wgSite(s store.WGSite) (wg.Site, error) {
	out := wg.Site{ID: s.ID, Name: s.Name, PublicKey: s.PublicKey, PresharedKey: s.PresharedKey,
		Endpoint: s.Endpoint, Keepalive: s.Keepalive, Enabled: s.Enabled}
	if s.PresharedKey == "" {
		return out, errors.New("its preshared key cannot be read (is the secret store locked?)")
	}
	addr, err := netip.ParseAddr(s.Address)
	if err != nil {
		return out, fmt.Errorf("address %q: %v", s.Address, err)
	}
	out.Address = addr
	for _, n := range s.Networks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return out, fmt.Errorf("network %q: %v", n, err)
		}
		out.Networks = append(out.Networks, p.Masked())
	}
	return out, nil
}

// syncWireGuard makes the endpoint match the settings. Every failure leaves
// the endpoint down, which closes every upstream that names a site: nothing
// here can make such an upstream reachable some other way.
func (e *Engine) syncWireGuard(ctx context.Context) {
	state := &wgState{enabled: e.store.GetSetting("wg_enabled", "") == "1"}
	defer func() {
		if state.err != "" {
			log.Printf("wireguard: %s", state.err)
		}
		e.wgState.Store(state)
	}()
	if !state.enabled {
		e.wg.Close()
		return
	}
	fail := func(format string, args ...any) {
		state.err = fmt.Sprintf(format, args...)
		e.wg.Close()
	}
	port, network, endpoint, err := WGSettings(e.store)
	if err != nil {
		fail("%v", err)
		return
	}
	state.port, state.network, state.endpoint = port, network, endpoint
	private := e.store.GetSetting("wg_private_key", "")
	if private == "" {
		// First use. In a locked store the read above gives "" for a key that
		// exists, and the write below is refused, so an existing key is never
		// replaced by accident.
		if private, err = wg.NewPrivateKey(); err == nil {
			err = e.store.SetSetting("wg_private_key", private)
		}
		if err != nil {
			fail("the server key cannot be created or stored: %v", err)
			return
		}
	}
	if state.publicKey, err = wg.PublicKey(private); err != nil {
		fail("server key: %v", err)
		return
	}
	stored, err := e.store.ListWGSites()
	if err != nil {
		fail("sites: %v", err)
		return
	}
	cfg := wg.Config{PrivateKey: private, ListenPort: port, Address: wg.TunnelAddress(network)}
	for _, s := range stored {
		site, err := wgSite(s)
		if err != nil {
			log.Printf("wireguard: site %q is left out: %v", s.Name, err)
			continue
		}
		cfg.Sites = append(cfg.Sites, site)
	}
	if err := e.wg.Apply(ctx, cfg); err != nil {
		fail("%v", err)
	}
}

// wgReresolveEvery is how often endpoint names are looked up again.
const wgReresolveEvery = 5 * time.Minute

// reresolveWireGuard keeps sites with a dynamic-DNS endpoint reachable.
func (e *Engine) reresolveWireGuard() {
	for {
		time.Sleep(wgReresolveEvery)
		if st := e.wgState.Load(); st != nil && st.enabled {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			e.wg.Reresolve(ctx)
			cancel()
		}
	}
}

// WGStatus reports the endpoint and its sites.
func (e *Engine) WGStatus() WGStatus {
	out := WGStatus{Port: wgDefaultPort, Network: wgDefaultNetwork, Sites: []wg.SiteStatus{}}
	st := e.wgState.Load()
	if st == nil {
		return out
	}
	out.Enabled, out.Error, out.PublicKey, out.Endpoint = st.enabled, st.err, st.publicKey, st.endpoint
	if st.port > 0 {
		out.Port = st.port
	}
	if st.network.IsValid() {
		out.Network, out.Address = st.network.String(), wg.TunnelAddress(st.network).String()
	}
	if sites := e.wg.Status(); sites != nil {
		out.Running, out.Sites = true, sites
	}
	out.Resets = e.wg.Resets()
	return out
}

// wgPort is the UDP port the endpoint occupies, or 0 when it is off.
func (e *Engine) wgPort() int {
	if st := e.wgState.Load(); st != nil && st.enabled {
		return st.port
	}
	return 0
}

// dialTarget is the one way quicgate connects to an upstream or a stream
// target. via 0 is the host network. Any other value is a WireGuard site, and
// then the host network is never used: an error from the tunnel is final.
func (e *Engine) dialTarget(ctx context.Context, via int64, network, addr string) (net.Conn, error) {
	if via == 0 {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return e.wg.DialContext(ctx, via, network, addr)
}

// dialTargetTimeout is dialTarget for callers without a context.
func (e *Engine) dialTargetTimeout(via int64, network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return e.dialTarget(ctx, via, network, addr)
}

// upstreamKey identifies a backend for health checks and load balancing. The
// site is part of it: the same address behind a site is another machine.
func upstreamKey(u store.Upstream) string {
	key := u.Scheme + "://" + hostPort(u.Host, u.Port)
	if u.Via > 0 {
		key += "|site=" + strconv.FormatInt(u.Via, 10)
	}
	return key
}

// viaCtxKey carries the chosen backend's site from the proxy's Rewrite to the
// transport.
type viaCtxKey struct{}

func withVia(r *http.Request, via int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), viaCtxKey{}, via))
}

// viaTransports is a host's set of connection pools: one http.Transport per
// place its backends are reached through (the host network, or a site). Go
// pools connections by scheme and address, so one shared transport would hand
// a connection to 192.168.1.10 on the local network to a request meant for
// 192.168.1.10 behind a site, or the other way round (S46).
type viaTransports struct {
	mu    sync.Mutex
	byVia map[int64]*http.Transport
}

var errNoSiteRecorded = errors.New("no route recorded for this backend: refusing to guess between the local network and a WireGuard site")

func (v *viaTransports) RoundTrip(req *http.Request) (*http.Response, error) {
	via, ok := req.Context().Value(viaCtxKey{}).(int64)
	if !ok {
		// Every Rewrite records the backend's site, 0 included. A request that
		// arrives here without one must not default to the host network.
		return nil, errNoSiteRecorded
	}
	t := v.byVia[via]
	if t == nil {
		return nil, errNoSiteRecorded
	}
	return t.RoundTrip(req)
}

// CloseIdleConnections drops the pooled connections, when a reload replaces
// the route these pools belong to.
func (v *viaTransports) CloseIdleConnections() {
	if v == nil {
		return
	}
	for _, t := range v.byVia {
		t.CloseIdleConnections()
	}
}

// newHostTransports builds the pools a host needs.
func (e *Engine) newHostTransports(h store.Host) *viaTransports {
	v := &viaTransports{byVia: map[int64]*http.Transport{}}
	vias := map[int64]bool{}
	for _, u := range append(append([]store.Upstream{h.Upstream}, h.Upstreams...), locationUpstreamsOf(h)...) {
		vias[u.Via] = true
	}
	ids := make([]int64, 0, len(vias))
	for via := range vias {
		ids = append(ids, via)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, via := range ids {
		via := via
		v.byVia[via] = newUpstreamTransport(h, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return e.dialTarget(ctx, via, network, addr)
		})
	}
	return v
}

func locationUpstreamsOf(h store.Host) []store.Upstream {
	out := make([]store.Upstream, 0, len(h.Locations))
	for _, l := range h.Locations {
		out = append(out, l.Upstream)
	}
	return out
}
