package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/transip"
	"github.com/mholt/acmez/v3"
	"github.com/quic-go/quic-go/http3"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// Config is the engine's static (process-level) configuration.
type Config struct {
	HTTPAddr   string // ":80"
	HTTPSAddr  string // ":443", also the UDP port for HTTP/3
	DataDir    string
	ACMEEmail  string
	ACMEStage  bool   // use Let's Encrypt staging CA
	DisableTLS bool   // dev mode: no TLS/QUIC listeners at all
	DisableH3  bool   // skip the HTTP/3 (QUIC) listener + Alt-Svc; force clients to h2
	UPnP       bool   // request router port forwards via UPnP IGD
	Version    string // build version, surfaced in the UI/API
	// AdminAddr is where the admin UI listens. The engine does not serve it,
	// but the VPN forwarder must know its port to keep devices away from it.
	AdminAddr string
}

// Version returns the running build version.
func (e *Engine) Version() string { return e.cfg.Version }

// Info reports process-level listener/feature configuration for the overview
// dashboard (the parts of Config the admin package cannot read directly).
type Info struct {
	Version   string `json:"version"`
	HTTPAddr  string `json:"httpAddr"`
	HTTPSAddr string `json:"httpsAddr"`
	TLS       bool   `json:"tls"`
	HTTP3     bool   `json:"http3"`
	UPnP      bool   `json:"upnp"`
	StartedAt int64  `json:"startedAt"` // unix time the engine was created
}

// Info returns the engine's listener/feature summary.
func (e *Engine) Info() Info {
	return Info{
		Version:   e.cfg.Version,
		HTTPAddr:  e.cfg.HTTPAddr,
		HTTPSAddr: e.cfg.HTTPSAddr,
		TLS:       !e.cfg.DisableTLS,
		HTTP3:     !e.cfg.DisableTLS && !e.cfg.DisableH3,
		UPnP:      e.cfg.UPnP,
		StartedAt: e.started.Unix(),
	}
}

type route struct {
	host  store.Host
	proxy http.Handler
	// warnings are configuration problems that made part of this route fail
	// closed (an unresolvable access-list hostname, a missing reference, an
	// unusable client CA), shown in the effective-config viewer.
	warnings []string
	// transports are the route's connection pools, one per place its backends
	// are reached through. Nil for routes that proxy nothing.
	transports *viaTransports
}

type routingTable struct {
	exact    map[string]*route // "app.example.com"
	wildcard map[string]*route // "example.com" for "*.example.com"
}

// routeName normalises a Host header or SNI for routing: lower case, no port,
// and no trailing dot ("example.com." is the same DNS name as "example.com", so
// it goes through the same host and the same gates).
func routeName(hostport string) string {
	name := strings.ToLower(hostport)
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	return strings.TrimSuffix(name, ".")
}

// metricLabel names the configured route a request belongs to, for per-host
// metrics: the exact domain, "*.suffix" for a wildcard route, or "_unmatched".
// Labels therefore stay bounded by the configuration whatever Host a client
// sends.
func (t *routingTable) metricLabel(hostport string) string {
	name := routeName(hostport)
	if _, ok := t.exact[name]; ok {
		return name
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		if _, ok := t.wildcard[name[i+1:]]; ok {
			return "*." + name[i+1:]
		}
	}
	return "_unmatched"
}

func (t *routingTable) lookup(hostport string) *route {
	name := routeName(hostport)
	if r, ok := t.exact[name]; ok {
		return r
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		if r, ok := t.wildcard[name[i+1:]]; ok {
			return r
		}
	}
	return nil
}

// Engine owns the routing table and all data-plane listeners.
type Engine struct {
	cfg     Config
	store   *store.Store
	table   atomic.Pointer[routingTable]
	magic   *certmagic.Config
	acme    *certmagic.ACMEIssuer
	h3      *http3.Server
	streams *StreamManager
	upnp    *UPnPManager

	// certCache is magic's certificate cache, and customCerts the entries
	// loadCustomCerts put in it (by cache hash), so a reload can unload a
	// custom certificate that was replaced, restored over or is no longer used.
	certCache   *certmagic.Cache
	customCerts map[string]bool

	acmeStaging   bool
	acmeEmail     string
	acmeDNS       string
	acmeDNSConfig string
	acmeCAURL     string
	certs         *certTracker
	accessLog     *accessLogger
	traffic       *trafficStats // history behind the overview charts
	started       time.Time
	health        *healthChecker
	geo           *geoDB
	ban           *banManager
	// wg is the embedded WireGuard endpoint. It exists always and runs only
	// while wg_enabled is on; wgState is what the last reload made of it.
	wg      *wg.Manager
	wgState atomic.Pointer[wgState]
	// vpnOwners says who each SSO-enrolled device belongs to, for VPN rules
	// about users and groups. Rebuilt at every reload.
	vpnOwners atomic.Pointer[map[int64]vpnOwner]
	flowLog   *flowLogger
	portal    *portalState

	banCfg        atomic.Pointer[banConfig] // compiled at reload; nil (auto-ban off) before the first
	caPoolCache   sync.Map
	reloadMu      sync.Mutex                     // serializes concurrent Reload callers
	dockerHosts   atomic.Pointer[[]store.Host]   // in-memory hosts from the Docker label provider
	dockerStreams atomic.Pointer[[]store.Stream] // in-memory L4 streams from the Docker label provider
	wgSeenMu      sync.Mutex                     // guards wgSeen
	wgSeen        map[string]wg.PeerStatus       // the peers' byte totals at the last look, for the traffic overview
	publicReqs    publicRequests                 // what is being served on the public listeners, per host
	realIP        atomic.Pointer[realIPConfig]   // compiled trusted-proxy / real-client-IP config
	oidcProviders sync.Map                       // issuer -> *discoveredProvider (lazy IdP discovery)
	oidcSecretMu  sync.Mutex
	oidcSecretKey []byte    // HMAC key for SSO session cookies, persisted in settings
	dns           *dnsCache // access-list hostname resolution with last-known-good fallback
}

// SetDockerRoutes replaces the hosts and streams derived from Docker labels and
// rebuilds the routing table. Called by the Docker provider on every reconcile;
// they are merged after the database config, so a manual host or stream always
// wins a conflict. Nothing here is persisted: the set re-derives from live
// containers on the next reconcile and at startup.
func (e *Engine) SetDockerRoutes(hosts []store.Host, streams []store.Stream) {
	hc := make([]store.Host, len(hosts))
	copy(hc, hosts)
	e.dockerHosts.Store(&hc)
	sc := make([]store.Stream, len(streams))
	copy(sc, streams)
	e.dockerStreams.Store(&sc)
	if err := e.Reload(context.Background()); err != nil {
		log.Printf("engine: reload after docker change: %v", err)
	}
}

func New(cfg Config, st *store.Store) *Engine {
	e := &Engine{cfg: cfg, store: st, streams: NewStreamManager(), health: newHealthChecker(), dns: newDNSCache(), started: time.Now(), wg: wg.New()}
	e.health.dial = e.dialTargetTimeout
	e.streams.dial = e.dialTargetTimeout
	e.wg.SetListeners(wg.Listeners{TCP: []uint16{80, 443, 53}, UDP: []uint16{53}, OnStart: e.serveTunnel})
	if cfg.DataDir != "" {
		e.wg.SetStateFile(cfg.DataDir + "/wg-endpoints.json")
		e.flowLog = newFlowLogger(cfg.DataDir)
		e.wg.SetFlowLog(e.flowLog.record)
	}
	e.portal = newPortalState()
	go e.reresolveWireGuard()
	go e.renewLeases()
	e.acmeStaging = cfg.ACMEStage
	e.acmeEmail = cfg.ACMEEmail
	e.certs = newCertTracker(func() string { return st.GetSetting("notify_url", "") })
	e.accessLog = newAccessLogger(cfg.DataDir)
	e.accessLog.hostLabel = func(host string) string { return e.table.Load().metricLabel(host) }
	e.geo = openGeoDB(cfg.DataDir + "/GeoLite2-Country.mmdb")
	e.ban = newBanManager(func() banConfig {
		if c := e.banCfg.Load(); c != nil {
			return *c
		}
		return banConfig{}
	}, e.certs.send)
	if cfg.DataDir != "" {
		e.ban.persistTo(cfg.DataDir + "/bans.json")
	}
	e.traffic = newTrafficStats(e.accessLog, e.ban, e.streams, e.geo, cfg.DataDir)
	e.streams.traffic = e.traffic
	e.accessLog.client = e.traffic.countClient
	if cfg.UPnP {
		e.upnp = NewUPnPManager(3600)
		e.ban.own.external = e.upnp.ExternalIP
	}
	e.table.Store(&routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}})

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return e.magic, nil },
	})
	e.certCache = cache
	// No OnDemand: the domain set is known, so ManageAsync obtains every
	// managed cert proactively in the background. This also makes unknown-SNI
	// noise (scanners, retired hostnames) fail the handshake fast instead of
	// contending with real issuance on the on-demand path.
	e.magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.DataDir + "/certs"},
		OnEvent: e.certs.handle,
	})
	e.buildIssuer()
	return e
}

// buildIssuer (re)creates the ACME issuer from the current staging/email
// fields plus any configured DNS-01 provider, and wires it into the magic
// config. Called at startup and whenever those settings change.
func (e *Engine) buildIssuer() {
	ca := certmagic.LetsEncryptProductionCA
	if e.acmeStaging {
		ca = certmagic.LetsEncryptStagingCA
	}
	if custom := e.store.GetSetting("acme_ca_url", ""); custom != "" {
		ca = custom // ZeroSSL, Buypass, internal step-ca, etc.
	}
	tmpl := certmagic.ACMEIssuer{
		CA:     ca,
		Email:  e.acmeEmail,
		Agreed: true,
	}
	if solver := e.dnsSolver(); solver != nil {
		tmpl.DNS01Solver = solver
		log.Printf("engine: DNS-01 solver active (%s), wildcard certs enabled", e.acmeDNS)
	}
	e.acme = certmagic.NewACMEIssuer(e.magic, tmpl)
	e.magic.Issuers = []certmagic.Issuer{e.acme}
}

// dnsSolver builds a DNS-01 solver from the configured provider, or nil.
func (e *Engine) dnsSolver() acmez.Solver {
	switch e.acmeDNS {
	case "transip":
		var cfg struct {
			Login      string `json:"login"`
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal([]byte(e.acmeDNSConfig), &cfg); err != nil || cfg.Login == "" || cfg.PrivateKey == "" {
			log.Printf("engine: transip DNS config invalid, DNS-01 disabled")
			return nil
		}
		return &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &transip.Provider{AuthLogin: cfg.Login, PrivateKey: cfg.PrivateKey},
		}}
	}
	return nil
}

// applyACMESettings reads ACME overrides from the store and rebuilds the
// issuer only when any of them changed.
func (e *Engine) applyACMESettings() {
	staging := e.cfg.ACMEStage
	if v := e.store.GetSetting("acme_staging", ""); v != "" {
		staging = v == "1"
	}
	email := e.store.GetSetting("acme_email", e.cfg.ACMEEmail)
	dns := e.store.GetSetting("acme_dns_provider", "")
	dnsConfig := e.store.GetSetting("acme_dns_config", "")
	caURL := e.store.GetSetting("acme_ca_url", "")
	if staging == e.acmeStaging && email == e.acmeEmail && dns == e.acmeDNS && dnsConfig == e.acmeDNSConfig && caURL == e.acmeCAURL {
		return
	}
	e.acmeStaging, e.acmeEmail, e.acmeDNS, e.acmeDNSConfig, e.acmeCAURL = staging, email, dns, dnsConfig, caURL
	e.buildIssuer()
	log.Printf("engine: ACME settings changed (staging=%v, email=%q, dns=%q), issuer rebuilt", staging, email, dns)
}

// Reload rebuilds the routing table from the store and swaps it in atomically,
// then kicks off cert management for any new domains. No listener restarts.
func (e *Engine) Reload(ctx context.Context) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	e.applyACMESettings()
	e.buildRealIP()
	banCfg := e.banConfig()
	e.banCfg.Store(&banCfg)
	e.ban.liftExempt()
	e.syncOIDCSecret()
	e.syncWireGuard(ctx)
	hosts, err := e.store.ListHosts()
	if err != nil {
		return err
	}
	lists, err := e.store.ListAccessLists()
	if err != nil {
		return err
	}
	access := map[int64]*compiledAccess{}
	for _, a := range lists {
		access[a.ID] = compileAccess(a, e.geo, e.ban, e.dns)
		access[a.ID].vpnMatch = e.vpnSubjectMatches
	}
	streams, err := e.store.ListStreams()
	if err != nil {
		return err
	}
	oidcList, err := e.store.ListOIDCProviders()
	if err != nil {
		return err
	}
	oidcProv := map[int64]store.OIDCProvider{}
	for _, p := range oidcList {
		oidcProv[p.ID] = p
	}
	e.loadCustomCerts(hosts)
	t := &routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}}
	healthTargets := map[string]healthTarget{}
	var managed []string

	// place installs one host's routes. Database hosts are placed first; hosts
	// from the Docker label provider are placed with fromDocker=true, so a
	// manual host always wins a name conflict (the docker route for that domain
	// is dropped rather than overriding explicit config).
	place := func(h store.Host, fromDocker bool) {
		if !h.Enabled {
			return
		}
		var acl *compiledAccess
		if h.AccessListID != nil {
			if acl = access[*h.AccessListID]; acl == nil {
				// A reference to a deleted list must close the host, never open it.
				log.Printf("engine: host %v names access list %d, which does not exist; the host is closed", h.Domains, *h.AccessListID)
				acl = deniedAccess(fmt.Sprintf("access list %d", *h.AccessListID))
			}
		}
		r := e.buildRoute(h, acl, access, oidcProv)
		r.warnings = e.routeWarnings(h, acl, access)
		placed := false
		for _, d := range h.Domains {
			if strings.HasPrefix(d, "*.") {
				key := d[2:]
				if fromDocker {
					if _, taken := t.wildcard[key]; taken {
						continue
					}
				}
				t.wildcard[key] = r
			} else {
				if fromDocker {
					if _, taken := t.exact[d]; taken {
						continue
					}
				}
				t.exact[d] = r
			}
			placed = true
			if h.CertMode == "auto" {
				managed = append(managed, d)
			}
		}
		// Only probe/health-check upstreams we actually routed to.
		if !placed {
			return
		}
		for _, u := range append([]store.Upstream{h.Upstream}, h.Upstreams...) {
			if u.Host != "" {
				healthTargets[upstreamKey(u)] = healthTarget{scheme: u.Scheme, hostport: hostPort(u.Host, u.Port), via: u.Via}
			}
		}
	}

	for _, h := range hosts {
		place(h, false)
	}
	if dh := e.dockerHosts.Load(); dh != nil {
		for _, h := range *dh {
			place(h, true)
		}
	}
	old := e.table.Swap(t)
	// Whoever is connected from outside to a host that just left the public
	// side is disconnected now (QG-03).
	e.endNoLongerPublic(t)
	e.health.setTargets(healthTargets)
	// The replaced routes' pooled connections go now, not when they time out:
	// a backend that moved behind another site must not be served from a
	// connection that was opened to the old place.
	if old != nil {
		for _, r := range old.exact {
			r.transports.CloseIdleConnections()
		}
		for _, r := range old.wildcard {
			r.transports.CloseIdleConnections()
		}
	}

	// Merge Docker-provider streams after the database streams, dropping any
	// whose listen port collides with a database stream, another docker stream,
	// or a port the engine itself occupies. Manual config and the proxy win.
	if ds := e.dockerStreams.Load(); ds != nil && len(*ds) > 0 {
		used := map[int]bool{}
		mark := func(s store.Stream) {
			last := s.ListenPort
			if s.ListenPortEnd > s.ListenPort {
				last = s.ListenPortEnd
			}
			for p := s.ListenPort; p <= last; p++ {
				used[p] = true
			}
		}
		for _, p := range e.ReservedPorts() {
			used[p] = true
		}
		for _, s := range streams {
			mark(s)
		}
		for _, s := range *ds {
			if used[s.ListenPort] {
				log.Printf("engine: docker stream on port %d skipped (port already in use)", s.ListenPort)
				continue
			}
			streams = append(streams, s)
			mark(s)
		}
	}

	e.streams.Sync(streams, e.loadStreamCert, func(id int64) *compiledAccess { return access[id] })
	if e.upnp != nil {
		var mappings []PortMapping
		if p := e.wgPort(); p > 0 {
			mappings = append(mappings, PortMapping{Proto: "UDP", Port: uint16(p)})
		}
		if p := portOf(e.cfg.HTTPAddr); p > 0 {
			mappings = append(mappings, PortMapping{Proto: "TCP", Port: uint16(p)})
		}
		if p := portOf(e.cfg.HTTPSAddr); p > 0 && !e.cfg.DisableTLS {
			mappings = append(mappings,
				PortMapping{Proto: "TCP", Port: uint16(p)},
				PortMapping{Proto: "UDP", Port: uint16(p)})
		}
		for _, s := range streams {
			if !s.Enabled {
				continue
			}
			last := s.ListenPort
			if s.ListenPortEnd > 0 {
				last = s.ListenPortEnd
			}
			for port := s.ListenPort; port <= last; port++ {
				if s.Protocol == "tcp" || s.Protocol == "both" {
					mappings = append(mappings, PortMapping{Proto: "TCP", Port: uint16(port)})
				}
				if s.Protocol == "udp" || s.Protocol == "both" {
					mappings = append(mappings, PortMapping{Proto: "UDP", Port: uint16(port)})
				}
			}
		}
		// User-defined router forwards straight to other LAN hosts (no proxy).
		if pfs, err := e.store.ListPortForwards(); err == nil {
			for _, p := range pfs {
				if !p.Enabled {
					continue
				}
				if p.Protocol == "tcp" || p.Protocol == "both" {
					mappings = append(mappings, PortMapping{Proto: "TCP", Port: uint16(p.ExtPort), IntIP: p.IntIP, IntPort: uint16(p.IntPort)})
				}
				if p.Protocol == "udp" || p.Protocol == "both" {
					mappings = append(mappings, PortMapping{Proto: "UDP", Port: uint16(p.ExtPort), IntIP: p.IntIP, IntPort: uint16(p.IntPort)})
				}
			}
		}
		go e.upnp.Sync(mappings)
	}
	if len(managed) > 0 && !e.cfg.DisableTLS {
		// Detach from the caller's context: an admin API request that triggers
		// Reload would otherwise cancel background issuance when it returns.
		if err := e.magic.ManageAsync(context.WithoutCancel(ctx), managed); err != nil {
			log.Printf("engine: cert management: %v", err)
		}
	}
	log.Printf("engine: routing table reloaded, %d exact + %d wildcard routes", len(t.exact), len(t.wildcard))
	return nil
}

// loadCustomCerts caches any user-uploaded certificates so the TLS listener
// serves them for their host without ACME. Idempotent across reloads, and it
// unloads the certificates it cached earlier that are no longer current: the
// cache keeps every certificate it is given, so a replaced or restored-over
// certificate would otherwise go on being served for the same name.
func (e *Engine) loadCustomCerts(hosts []store.Host) {
	if e.cfg.DisableTLS {
		return
	}
	current := map[string]bool{}
	defer func() {
		var stale []string
		for hash := range e.customCerts {
			if !current[hash] {
				stale = append(stale, hash)
			}
		}
		if len(stale) > 0 {
			e.certCache.Remove(stale)
		}
		e.customCerts = current
	}()
	seen := map[int64]bool{}
	for _, h := range hosts {
		if h.CertMode != "custom" || h.CertID == nil || seen[*h.CertID] {
			continue
		}
		seen[*h.CertID] = true
		certPEM, keyPEM, err := e.store.GetCustomCertPEM(*h.CertID)
		if err != nil {
			log.Printf("engine: custom cert %d: %v", *h.CertID, err)
			continue
		}
		hash, err := e.magic.CacheUnmanagedCertificatePEMBytes(context.Background(), []byte(certPEM), []byte(keyPEM), nil)
		if err != nil {
			log.Printf("engine: cache custom cert %d: %v", *h.CertID, err)
			continue
		}
		current[hash] = true
	}
}

// loadStreamCert resolves a custom cert id to a tls.Certificate for TLS
// termination on streams.
func (e *Engine) loadStreamCert(id int64) (tls.Certificate, bool) {
	certPEM, keyPEM, err := e.store.GetCustomCertPEM(id)
	if err != nil {
		return tls.Certificate{}, false
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, false
	}
	return cert, true
}

// defaultMaxIdleConnsPerHost sizes the keep-alive pool the proxy holds open to
// each backend. Go's http.Transport default is 2, far too low for a reverse
// proxy: under concurrent load to one upstream it opens and closes connections
// faster than it pools them, paying a fresh dial + TLS handshake per burst and,
// on Windows, exhausting ephemeral ports (which surfaces as 502s). A large pool
// lets a hot host reuse connections instead of churning them. Override per host
// via Options.MaxIdleConnsPerHost.
const defaultMaxIdleConnsPerHost = 256

// newUpstreamTransport builds the reverse-proxy transport for one host from its
// typed options. The same transport backs the host's default proxy and every
// location proxy, so its idle-connection budget is sized for the whole backend
// set (primary + pool + locations), not a single target.
func newUpstreamTransport(h store.Host, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	o := h.Options
	dialTimeout := 10 * time.Second
	if o.DialTimeoutSec > 0 {
		dialTimeout = time.Duration(o.DialTimeoutSec) * time.Second
	}
	idleTimeout := 90 * time.Second
	if o.IdleTimeoutSec > 0 {
		idleTimeout = time.Duration(o.IdleTimeoutSec) * time.Second
	}
	maxIdlePerHost := defaultMaxIdleConnsPerHost
	if o.MaxIdleConnsPerHost > 0 {
		maxIdlePerHost = o.MaxIdleConnsPerHost
	}
	// MaxIdleConns caps idle conns across the whole transport, which is shared by
	// the primary upstream, the load-balancing pool and any location proxies. A
	// per-host pool can never exceed this total, so scale it by the number of
	// distinct backends — otherwise Go's default of 100 would throttle a large
	// MaxIdleConnsPerHost back down.
	backends := 1 + len(h.Upstreams) + len(h.Locations)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			return dial(ctx, network, addr)
		},
		IdleConnTimeout:       idleTimeout,
		MaxIdleConnsPerHost:   maxIdlePerHost,
		MaxIdleConns:          maxIdlePerHost * backends,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if o.ResponseHeaderTimeoutSec > 0 {
		transport.ResponseHeaderTimeout = time.Duration(o.ResponseHeaderTimeoutSec) * time.Second
	}
	if h.Upstream.Scheme == "https" {
		tc := &tls.Config{InsecureSkipVerify: o.SkipTLSVerify}
		if o.UpstreamSNI != "" {
			tc.ServerName = o.UpstreamSNI
		}
		transport.TLSClientConfig = tc
	}
	return transport
}

// buildRoute compiles one host's typed options into a ready http.Handler chain.
func (e *Engine) buildRoute(h store.Host, acl *compiledAccess, acls map[int64]*compiledAccess, oidcProv map[int64]store.OIDCProvider) *route {
	o := h.Options
	// One gate per distinct SSO policy this host uses: the host default plus any
	// named by a path rule. Rules on the same provider still get their own gate
	// whenever their policy differs, so a stricter /admin/ rule is never
	// collapsed into the broader host policy. They share a siblings map so the
	// single callback path can be finished by whichever gate started the login.
	siblings := map[string]*oidcGate{}
	newGate := func(auth store.OIDCAuth) *oidcGate {
		key := oidcGateKey(auth)
		if g, ok := siblings[key]; ok {
			return g
		}
		g := e.newOIDCGate(auth, oidcProv)
		g.siblings = siblings
		siblings[key] = g
		return g
	}
	var sso *oidcGate
	if o.OIDC != nil {
		sso = newGate(*o.OIDC)
	}
	for _, r := range o.AuthRules {
		if r.Mode == "oidc" && r.OIDC != nil {
			newGate(*r.OIDC)
		}
	}

	// Maintenance mode short-circuits every request to a 503 page, whatever the
	// host type. Access lists and rate limits still apply (via wrapCommon).
	if o.Maintenance {
		return &route{host: h, proxy: wrapCommon(h.Domains, maintenanceHandler(o.MaintenanceHTML), o, acl, acls, sso, newGate)}
	}

	// Non-proxy hosts skip the proxy machinery entirely, but still get the
	// access-list, rate-limit and exploit-filter wrappers.
	switch h.Type {
	case "redirect":
		var handler http.Handler = deadHandler()
		if h.Redirect != nil {
			handler = buildRedirectHandler(*h.Redirect)
		}
		return &route{host: h, proxy: wrapCommon(h.Domains, handler, o, acl, acls, sso, newGate)}
	case "dead":
		return &route{host: h, proxy: wrapCommon(h.Domains, deadHandler(), o, acl, acls, sso, newGate)}
	case "vpn-portal":
		// The portal does its own login; an access list in front of it still
		// applies, a host-level OIDC gate would only get in its way.
		return &route{host: h, proxy: wrapCommon(h.Domains, e.portalHandler(h), o, acl, acls, nil, newGate)}
	case "static":
		fs := http.FileServer(http.Dir(h.StaticRoot))
		return &route{host: h, proxy: wrapCommon(h.Domains, fs, o, acl, acls, sso, newGate)}
	}

	// Build the balancer target list: primary plus any pool members.
	bal := &balancer{health: e.health}
	pool := append([]store.Upstream{h.Upstream}, h.Upstreams...)
	// viaOf gives the site of a backend by its URL. Within a host an address
	// is only ever reached one way (the store refuses anything else), so the
	// URL is enough to tell.
	viaOf := map[string]int64{}
	for _, u := range pool {
		hp := hostPort(u.Host, u.Port)
		bal.targets = append(bal.targets, balTarget{
			key: upstreamKey(u), url: u.Scheme + "://" + hp, hostport: hp,
			id: targetID(upstreamKey(u)),
		})
		viaOf[u.Scheme+"://"+hp] = u.Via
	}
	target := &url.URL{Scheme: h.Upstream.Scheme, Host: hostPort(h.Upstream.Host, h.Upstream.Port)}

	transport := e.newHostTransports(h)

	// Buffered by default; buffering=false flushes every write for SSE and
	// long-poll upstreams. Websockets bypass this path entirely.
	flush := time.Duration(0)
	if o.Buffering != nil && !*o.Buffering {
		flush = -1
	}

	rewrite := compileRewrite(o.PathRewrite)
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: flush,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Pick a (healthy) backend per request for load balancing.
			pick := target
			if len(bal.targets) > 1 {
				if o.StickySessions {
					cookieVal := ""
					if ck, err := pr.In.Cookie(stickyCookieName); err == nil {
						cookieVal = ck.Value
					}
					u, id := bal.stickyPick(cookieVal)
					if pu, err := url.Parse(u); err == nil {
						pick = pu
					}
					pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), stickyKey, stickyInfo{id: id, had: cookieVal == id}))
				} else if u, err := url.Parse(bal.pick()); err == nil {
					pick = u
				}
			}
			pr.Out = withVia(pr.Out, viaOf[pick.Scheme+"://"+pick.Host])
			pr.SetURL(pick)
			pr.SetXForwarded()
			setRealIP(pr)
			normalizeBodyless(pr)
			if rewrite != nil {
				pr.Out.URL.Path = rewrite.apply(pr.Out.URL.Path)
			}
			// Preserve the client's Host header by default (like Traefik/nginx
			// proxy_set_header Host $host) so host-validating backends work.
			if o.HostOverride != "" {
				pr.Out.Host = o.HostOverride
			} else {
				pr.Out.Host = pr.In.Host
			}
			applyHeaderRules(pr.Out.Header, o.RequestHeaders, pr.In)
		},
		ModifyResponse: func(resp *http.Response) error {
			if o.StickySessions && len(bal.targets) > 1 {
				if info, ok := resp.Request.Context().Value(stickyKey).(stickyInfo); ok && info.id != "" && !info.had {
					ck := &http.Cookie{Name: stickyCookieName, Value: info.id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
					resp.Header.Add("Set-Cookie", ck.String())
				}
			}
			if o.BlockIndexing {
				resp.Header.Set("X-Robots-Tag", "noindex, nofollow, nosnippet, noarchive")
			}
			applyHeaderRules(resp.Header, o.ResponseHeaders, nil)
			return nil
		},
		ErrorHandler: badGatewayHandler(target, o.BadGatewayHTML),
	}

	var handler http.Handler = proxy

	// Custom locations: route matching path prefixes to their own upstreams.
	if len(h.Locations) > 0 {
		handler = e.locationDispatcher(h, handler, transport)
	}

	// Response cache sits inside gzip so it stores uncompressed bodies and each
	// client still gets a per-request encoding.
	if o.CacheSec > 0 {
		handler = newRespCache(time.Duration(o.CacheSec)*time.Second, 0).wrap(handler)
	}

	if o.Compression {
		handler = gzipWrap(handler)
	}
	if o.MaxBodyMB > 0 {
		limit := int64(o.MaxBodyMB) << 20
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			inner.ServeHTTP(w, r)
		})
	}
	handler = wrapCommon(h.Domains, handler, o, acl, acls, sso, newGate)
	return &route{host: h, proxy: handler, transports: transport}
}

// normalizeBodyless drops the phantom request body HTTP/3 leaves on GET/HEAD.
//
// quic-go reports ContentLength -1 ("unknown") whenever a request carries no
// content-length header, which every browser GET omits. ReverseProxy then hands
// http.Transport a non-nil body of unknown length, so it frames the upstream
// request with Transfer-Encoding: chunked. Strict upstreams reject a chunked
// GET outright: lighttpd (Asustor ADM) answers 400 Bad Request for every path,
// before routing, so an h3 browser saw 400 everywhere while curl over HTTP/1.1
// worked. Go's h1 and h2 servers set ContentLength 0 for bodyless requests, so
// only h3 needs this.
//
// Limited to GET/HEAD: a body there is legal but meaningless, while POST/PUT
// legitimately stream unknown-length bodies that must stay chunked.
func normalizeBodyless(pr *httputil.ProxyRequest) {
	if pr.Out.ContentLength != -1 {
		return
	}
	switch pr.In.Method {
	case http.MethodGet, http.MethodHead:
		pr.Out.Body = http.NoBody
		pr.Out.ContentLength = 0
	}
}

// setRealIP adds the X-Real-IP header with the immediate client's address,
// matching what Traefik/nginx send by default. SetXForwarded already appended
// the client to X-Forwarded-For; X-Real-IP is the single real client IP that
// backends like Vaultwarden read (its default IP_HEADER) for logging and
// per-IP rate limiting.
func setRealIP(pr *httputil.ProxyRequest) {
	ip := pr.In.RemoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	if ip != "" {
		pr.Out.Header.Set("X-Real-IP", ip)
	}
}

// stickyKey carries the chosen backend id from Rewrite to ModifyResponse so the
// affinity cookie is set only when the backend changed.
type stickyCtxKey int

const stickyKey stickyCtxKey = 0
const stickyCookieName = "qg_affinity"

type stickyInfo struct {
	id  string
	had bool
}

// maintenanceHandler serves a 503 "under maintenance" page instead of proxying.
func maintenanceHandler(customHTML string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusServiceUnavailable)
		if customHTML != "" {
			fmt.Fprint(w, customHTML)
			return
		}
		fmt.Fprintf(w, errorPage, http.StatusServiceUnavailable, http.StatusServiceUnavailable, "Under maintenance")
	})
}

// wrapCommon applies the middleware shared by every host type, outermost
// first: path traversal check -> rate limit -> bad bots -> exploit filter ->
// identity header strip -> access list -> forward-auth -> OIDC SSO. With
// path-scoped auth rules configured, the auth layers become per-path (see
// pathauth.go); everything around them stays host-wide.
// A host with any identity-injecting gate (SSO on the host or on any path,
// forward auth) additionally strips those identity headers from every inbound
// request, public paths included, so an upstream that trusts them can never be
// fed a spoofed value through quicgate.
func wrapCommon(domains []string, handler http.Handler, o store.Options, acl *compiledAccess, acls map[int64]*compiledAccess, sso *oidcGate, newGate func(store.OIDCAuth) *oidcGate) http.Handler {
	hostGate := func(h http.Handler) http.Handler {
		if sso != nil {
			h = sso.wrap(h)
		}
		if o.ForwardAuth != nil && o.ForwardAuth.URL != "" {
			h = forwardAuth(o.ForwardAuth, h)
		}
		if acl != nil {
			h = acl.wrap(h)
		}
		return h
	}
	out := hostGate(handler)
	if len(o.AuthRules) > 0 {
		out = buildPathAuth(domains, o.AuthRules, o, acls, sso, newGate, handler, out)
	}
	// The strip sits OUTSIDE every gate: inbound spoofed values are removed
	// before any chain runs, and the gate's own injection happens after.
	if names := trustedIdentityHeaders(o); len(names) > 0 {
		out = stripHeaders(names, out)
	}
	// Abuse controls run before any authentication work, so a flood of
	// credential guesses or SSO redirects is throttled and filtered before it
	// costs a bcrypt comparison, a forward-auth call or an IdP round trip.
	if o.BlockExploits {
		out = blockExploits(out)
	}
	if o.BlockBadBots {
		out = blockBadBots(out)
	}
	if o.RateLimit != nil {
		out = newRateLimiter(o.RateLimit).wrap(out)
	}
	// Outermost of all: a path that means different things to quicgate's rules
	// and to the upstream can defeat every gate below, so refuse it first.
	// The request-auth record is attached before any gate can strip credentials.
	inner := rejectTraversal(out)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, withRequestAuth(r))
	})
}

// badGatewayHandler renders the upstream-down page, using a per-host custom
// HTML body when one is configured.
func badGatewayHandler(target *url.URL, customHTML string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy %s -> %s: %v", r.Host, target.Host, err)
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		if customHTML != "" {
			fmt.Fprint(w, customHTML)
			return
		}
		fmt.Fprintf(w, errorPage, status, status, http.StatusText(status))
	}
}

// locationDispatcher routes requests whose path matches a location prefix
// (longest wins) to that location's own upstream + rewrite; everything else
// falls through to the host's default handler.
func (e *Engine) locationDispatcher(h store.Host, def http.Handler, transport http.RoundTripper) http.Handler {
	type loc struct {
		prefix string
		proxy  http.Handler
	}
	var locs []loc
	for _, l := range h.Locations {
		target := &url.URL{Scheme: l.Upstream.Scheme, Host: hostPort(l.Upstream.Host, l.Upstream.Port)}
		rw := compileRewrite(l.PathRewrite)
		via := l.Upstream.Via
		lp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out = withVia(pr.Out, via)
				pr.SetURL(target)
				pr.SetXForwarded()
				setRealIP(pr)
				normalizeBodyless(pr)
				pr.Out.Host = pr.In.Host
				if rw != nil {
					pr.Out.URL.Path = rw.apply(pr.Out.URL.Path)
				}
			},
			ErrorHandler: badGatewayHandler(target, h.Options.BadGatewayHTML),
		}
		locs = append(locs, loc{prefix: l.Path, proxy: lp})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		best := -1
		for i, l := range locs {
			if strings.HasPrefix(r.URL.Path, l.prefix) && (best < 0 || len(l.prefix) > len(locs[best].prefix)) {
				best = i
			}
		}
		if best >= 0 {
			locs[best].proxy.ServeHTTP(w, r)
			return
		}
		def.ServeHTTP(w, r)
	})
}

// applyHeaderRules runs the ordered typed header mutations. Values support
// the placeholders {client_ip}, {host} and {scheme} when a request is given.
func applyHeaderRules(hdr http.Header, rules []store.HeaderRule, in *http.Request) {
	for _, r := range rules {
		switch r.Op {
		case "remove":
			hdr.Del(r.Name)
		case "set":
			hdr.Set(r.Name, expandPlaceholders(r.Value, in))
		case "add":
			hdr.Add(r.Name, expandPlaceholders(r.Value, in))
		}
	}
}

func expandPlaceholders(v string, in *http.Request) string {
	if in == nil || !strings.Contains(v, "{") {
		return v
	}
	ip := in.RemoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	scheme := "https"
	if in.TLS == nil {
		scheme = "http"
	}
	repl := strings.NewReplacer("{client_ip}", ip, "{host}", in.Host, "{scheme}", scheme)
	return repl.Replace(v)
}

// serveUnmatched handles requests for hostnames with no configured host,
// per the default-site setting: 404 page (default), custom HTML, or redirect.
func (e *Engine) serveUnmatched(w http.ResponseWriter, r *http.Request) {
	switch e.store.GetSetting("default_site", "404") {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, e.store.GetSetting("default_site_value", ""))
	case "redirect":
		if url := e.store.GetSetting("default_site_value", ""); url != "" {
			http.Redirect(w, r, url, http.StatusFound)
			return
		}
		serveDefault404(w)
	default:
		serveDefault404(w)
	}
}

// serveHTTPS is the shared handler behind the TLS (TCP) and QUIC (UDP) listeners.
func (e *Engine) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	t := e.table.Load()
	rt := t.lookup(r.Host)
	// A VPN-only host does not exist for a request from outside the tunnel:
	// the answer is the one an unknown host gets (S17).
	if rt == nil || (rt.host.Options.VPNOnly && !viaVPN(r)) {
		e.serveUnmatched(w, r)
		return
	}
	if !viaVPN(r) {
		var done func()
		r, done = e.publicReqs.track(rt, r)
		defer done()
	}
	if !e.clientCertOK(w, r, t, rt) {
		return
	}
	o := rt.host.Options
	if o.HSTS.Enabled {
		v := fmt.Sprintf("max-age=%d", o.HSTS.MaxAge)
		if o.HSTS.IncludeSubdomains {
			v += "; includeSubDomains"
		}
		if o.HSTS.Preload {
			v += "; preload"
		}
		w.Header().Set("Strict-Transport-Security", v)
	}
	switch {
	case o.HTTP3 != nil && !*o.HTTP3:
		// Host opted out of HTTP/3. Actively clear any Alt-Svc the browser
		// cached earlier (h3 hints live up to 30 days) so it drops h3 and
		// falls back to h2 for this host, while other hosts keep h3. Needed
		// for backends whose web clients misbehave over h3 (e.g. Vaultwarden).
		w.Header().Set("Alt-Svc", "clear")
	case e.h3 != nil && r.ProtoMajor < 3 && !viaVPN(r):
		// Advertise h3 so browsers upgrade to HTTP/3 on the next request.
		_ = e.h3.SetQUICHeaders(w.Header())
	}
	rt.proxy.ServeHTTP(w, r)
}

// serveHTTP handles plain port 80: ACME challenges (wrapped outside), the
// force-SSL redirect, and direct serving for certMode "none" hosts.
func (e *Engine) serveHTTP(w http.ResponseWriter, r *http.Request) {
	rt := e.table.Load().lookup(r.Host)
	if rt == nil || (rt.host.Options.VPNOnly && !viaVPN(r)) {
		e.serveUnmatched(w, r)
		return
	}
	if !viaVPN(r) {
		var done func()
		r, done = e.publicReqs.track(rt, r)
		defer done()
	}
	// A host that takes client certificates is HTTPS only, whatever its
	// force-SSL flag says: plain HTTP carries no certificate to check.
	if rt.host.ForceSSL || rt.host.Options.ClientCert != nil {
		code := http.StatusMovedPermanently
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			code = http.StatusPermanentRedirect
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code)
		return
	}
	rt.proxy.ServeHTTP(w, r)
}

// tlsConfig builds the TLS listener config: certmagic certificates plus a
// per-SNI minimum-version override from the host's typed TLS options.
func (e *Engine) tlsConfig() *tls.Config { return e.tlsConfigFor(false) }

// tlsConfigFor builds the TLS configuration of the public listeners, or of
// the listener inside the WireGuard tunnel. The public ones offer no
// certificate for a VPN-only host: not over TCP and, because HTTP/3 takes
// its configuration from the same one, not over QUIC either.
func (e *Engine) tlsConfigFor(tunnel bool) *tls.Config {
	base := e.magic.TLSConfig()
	base.NextProtos = append([]string{"h2", "http/1.1"}, base.NextProtos...)
	base.MinVersion = tls.VersionTLS12
	// TLS 1.2 AEAD suites only — drop the CBC-SHA suites SSL Labs flags WEAK.
	// (TLS 1.3 suites are fixed by Go and always strong.)
	base.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	base.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		r := e.table.Load().lookup(chi.ServerName)
		if r == nil {
			return nil, nil
		}
		o := r.host.Options
		if o.VPNOnly && !tunnel {
			return nil, errVPNOnlyName
		}
		needClone := o.MinTLSVersion == "1.3" || o.ClientCert != nil
		if !needClone {
			return nil, nil
		}
		c := base.Clone()
		c.GetConfigForClient = nil
		if o.MinTLSVersion == "1.3" {
			c.MinVersion = tls.VersionTLS13
		}
		if o.ClientCert != nil {
			if pool := e.clientCAPool(o.ClientCert.CAPEM); pool != nil {
				c.ClientCAs = pool
				if o.ClientCert.Mode == "request" {
					c.ClientAuth = tls.VerifyClientCertIfGiven
				} else {
					c.ClientAuth = tls.RequireAndVerifyClientCert
				}
			}
		}
		return c, nil
	}
	return base
}

// clientCAPool parses and caches a PEM CA bundle for mTLS verification. A
// bundle that does not parse is cached as nil (logged once): callers treat nil
// as "no usable policy" and refuse the request.
func (e *Engine) clientCAPool(pemStr string) *x509.CertPool {
	if pemStr == "" {
		return nil
	}
	if v, ok := e.caPoolCache.Load(pemStr); ok {
		return v.(*x509.CertPool)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		log.Printf("engine: mTLS CA bundle did not parse; hosts using it refuse every request")
		e.caPoolCache.Store(pemStr, (*x509.CertPool)(nil))
		return nil
	}
	e.caPoolCache.Store(pemStr, pool)
	return pool
}

// clientCertOK enforces a host's client-certificate policy on every request.
// The handshake applies the policy of the SNI name, but a client chooses the
// Host header independently, and HTTP/2 and HTTP/3 can carry several
// authorities over one connection. So a request is refused with 421 whenever
// its SNI selects a different host and either side takes client certificates,
// and the peer certificate is verified again against the requested host's
// current CA pool, which also covers a CA replaced on reload while an already
// verified connection stays open. Serves the TLS and QUIC listeners alike.
func (e *Engine) clientCertOK(w http.ResponseWriter, r *http.Request, t *routingTable, rt *route) bool {
	policy := rt.host.Options.ClientCert
	if r.TLS == nil {
		if policy == nil {
			return true
		}
		markBlocked(w, blockClientCert)
		http.Error(w, "client certificate required", http.StatusForbidden)
		return false
	}
	if sni := t.lookup(r.TLS.ServerName); sni != rt {
		if policy != nil || (sni != nil && sni.host.Options.ClientCert != nil) {
			markBlocked(w, blockClientCert)
			http.Error(w, "misdirected request: the TLS server name does not match this host", http.StatusMisdirectedRequest)
			return false
		}
	}
	if policy == nil {
		return true
	}
	pool := e.clientCAPool(policy.CAPEM)
	if pool == nil {
		markBlocked(w, blockClientCert)
		http.Error(w, "client certificate policy unavailable", http.StatusForbidden)
		return false
	}
	certs := r.TLS.PeerCertificates
	if len(certs) == 0 {
		if policy.Mode == "request" {
			return true
		}
		markBlocked(w, blockClientCert)
		http.Error(w, "client certificate required", http.StatusForbidden)
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		markBlocked(w, blockClientCert)
		http.Error(w, "client certificate not accepted", http.StatusForbidden)
		return false
	}
	return true
}

// routeWarnings collects the configuration problems that make parts of a host
// fail closed, for the effective-config viewer.
func (e *Engine) routeWarnings(h store.Host, acl *compiledAccess, access map[int64]*compiledAccess) []string {
	var out []string
	if acl != nil {
		out = append(out, acl.warnings...)
	}
	seen := map[int64]bool{}
	if h.AccessListID != nil {
		seen[*h.AccessListID] = true
	}
	for _, r := range h.Options.AuthRules {
		if r.Mode != "accessList" || r.AccessListID == nil || seen[*r.AccessListID] {
			continue
		}
		seen[*r.AccessListID] = true
		if a := access[*r.AccessListID]; a != nil {
			out = append(out, a.warnings...)
		} else {
			out = append(out, fmt.Sprintf("path %s: access list %d no longer exists, so the path refuses every request", r.Path, *r.AccessListID))
		}
	}
	if cc := h.Options.ClientCert; cc != nil && e.clientCAPool(cc.CAPEM) == nil {
		out = append(out, "the client certificate CA bundle does not parse, so the host refuses every request")
	}
	return out
}

// Run starts the data-plane listeners and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	if err := e.Reload(ctx); err != nil {
		return err
	}

	// Periodic reload re-resolves dynamic-DNS access-list hostnames.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := e.Reload(ctx); err != nil {
					log.Printf("engine: periodic reload: %v", err)
				}
			}
		}
	}()

	e.traffic.start(ctx)

	httpHandler := e.acme.HTTPChallengeHandler(e.wrapRealIP(e.ban.wrap(e.accessLog.wrap(e.serveHTTP))))
	httpSrv := newPublicServer(e.cfg.HTTPAddr, httpHandler, nil)
	errCh := make(chan error, 3)
	go func() {
		ln, err := e.listenCounted(e.cfg.HTTPAddr)
		if err == nil {
			err = httpSrv.Serve(ln)
		}
		errCh <- fmt.Errorf("http listener: %w", err)
	}()
	log.Printf("engine: http listening on %s", e.cfg.HTTPAddr)

	var httpsSrv *http.Server
	if !e.cfg.DisableTLS {
		tlsCfg := e.tlsConfig()
		httpsHandler := e.wrapRealIP(e.ban.wrap(e.accessLog.wrap(e.serveHTTPS)))
		httpsSrv = newPublicServer(e.cfg.HTTPSAddr, httpsHandler, tlsCfg)
		go func() {
			ln, err := e.listenCounted(e.cfg.HTTPSAddr)
			if err == nil {
				err = httpsSrv.ServeTLS(ln, "", "")
			}
			errCh <- fmt.Errorf("https listener: %w", err)
		}()

		// HTTP/3 is opt-out: when disabled we never create e.h3, which also
		// stops Alt-Svc advertisement (serveHTTPS checks e.h3 != nil), so
		// browsers never upgrade and existing ones fall back to h2.
		if !e.cfg.DisableH3 {
			e.h3 = e.newHTTP3Server(httpsHandler, tlsCfg)
			go func() { errCh <- fmt.Errorf("http3 listener: %w", e.h3.ListenAndServe()) }()
			log.Printf("engine: https + http/3 listening on %s (tcp+udp)", e.cfg.HTTPSAddr)
		} else {
			log.Printf("engine: https listening on %s (tcp); http/3 disabled", e.cfg.HTTPSAddr)
		}
	} else {
		log.Printf("engine: TLS disabled (dev mode), only plain http is served")
	}

	select {
	case <-ctx.Done():
		log.Printf("engine: shutting down (draining connections for up to 5s)")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		if httpsSrv != nil {
			_ = httpsSrv.Shutdown(shutdownCtx)
		}
		if e.h3 != nil {
			_ = e.h3.Close()
		}
		e.streams.StopAll()
		e.wg.Close()
		if e.upnp != nil {
			e.upnp.Close()
		}
		_ = e.accessLog.Close()
		if err := e.ban.closePersist(); err != nil {
			log.Printf("engine: save bans: %v", err)
		}
		if err := e.traffic.finish(time.Now()); err != nil {
			log.Printf("engine: save traffic history: %v", err)
		}
		log.Printf("engine: shutdown complete")
		return nil
	case err := <-errCh:
		return err
	}
}

// listenCounted opens a public TCP listener whose connections are counted
// against the listener's traffic statistics.
func (e *Engine) listenCounted(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return countedListener{Listener: ln, c: e.traffic.port("tcp:" + strconv.Itoa(portOf(addr)))}, nil
}

// newHTTP3Server builds the QUIC listener's server. quic-go counts every
// connection's bytes itself; the connection hook hands each one to the traffic
// statistics.
func (e *Engine) newHTTP3Server(handler http.Handler, tlsCfg *tls.Config) *http3.Server {
	return &http3.Server{
		Addr:        e.cfg.HTTPSAddr,
		Handler:     handler,
		TLSConfig:   http3.ConfigureTLSConfig(tlsCfg),
		ConnContext: e.traffic.quicConnContext("udp:" + strconv.Itoa(portOf(e.cfg.HTTPSAddr))),
	}
}

// TrafficReport returns the traffic history over a range: "1h", "6h", "24h"
// or "7d".
func (e *Engine) TrafficReport(rng string) (TrafficReport, error) {
	return e.traffic.report(rng, time.Now(), e.listenerTraffic())
}

// listenerTraffic describes every listener the engine runs, for the traffic
// report's port table.
func (e *Engine) listenerTraffic() []PortTraffic {
	var mapped map[string]bool
	if e.upnp != nil {
		mapped = e.upnp.Mapped()
	}
	var out []PortTraffic
	add := func(p PortTraffic) {
		p.Key = p.Proto + ":" + strconv.Itoa(p.Port)
		if e.upnp != nil {
			exposed := mapped[strings.ToUpper(p.Proto)+":"+strconv.Itoa(p.Port)]
			p.Exposed = &exposed
		}
		out = append(out, p)
	}
	if p := portOf(e.cfg.HTTPAddr); p > 0 {
		detail := "Plain HTTP: redirects to HTTPS and ACME challenges"
		if e.cfg.DisableTLS {
			detail = "Plain HTTP"
		}
		add(PortTraffic{Proto: "tcp", Port: p, Service: "HTTP", Detail: detail, State: "listening"})
	}
	if p := portOf(e.cfg.HTTPSAddr); p > 0 && !e.cfg.DisableTLS {
		add(PortTraffic{Proto: "tcp", Port: p, Service: "HTTPS", Detail: "HTTP/1.1 and HTTP/2 over TLS", State: "listening"})
		if !e.cfg.DisableH3 {
			add(PortTraffic{Proto: "udp", Port: p, Service: "HTTP/3", Detail: "QUIC", State: "listening"})
		}
	}
	// The WireGuard endpoint is a listener like the others: it holds a port,
	// the router maps it, and it carries traffic. Leaving it out made this list
	// disagree with the router's.
	if st := e.wgState.Load(); st != nil && st.enabled && st.port > 0 {
		sites, devices := e.wg.Status(), e.wg.DeviceStatus()
		row := PortTraffic{Proto: "udp", Port: st.port, Service: "WireGuard", State: "listening",
			Detail: fmt.Sprintf("VPN endpoint: %d sites, %d devices", len(sites), len(devices))}
		if sites == nil {
			row.State, row.Error = "failed", st.err
		}
		add(row)
	}
	for _, l := range e.streams.listeners() {
		s := l.stream
		detail := "to " + hostPort(s.ForwardHost, s.ForwardPort)
		switch {
		case l.proto == "tcp" && len(s.SNIRoutes) > 0:
			detail = fmt.Sprintf("TLS passthrough by SNI, %d routes", len(s.SNIRoutes))
		case l.proto == "tcp" && s.TerminateTLS:
			detail = "TLS terminated, " + detail
		}
		p := PortTraffic{Proto: l.proto, Port: s.ListenPort, Service: strings.ToUpper(l.proto) + " stream", Detail: detail,
			StreamID: s.ID, Docker: s.ID == 0, State: l.state, Error: l.err}
		if s.ListenPortEnd > s.ListenPort {
			p.PortEnd = s.ListenPortEnd
		}
		add(p)
	}
	return out
}

// hostPort joins a host and port into a dial/URL address, bracketing IPv6
// literals: "2001:db8::1" + 8080 -> "[2001:db8::1]:8080". A bare
// fmt.Sprintf("%s:%d") yields "2001:db8::1:8080", which net.Dial rejects with
// "too many colons in address", so every upstream/forward address goes through
// this.
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func portOf(addr string) int {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// StreamStatuses reports, per stream listener, whether it is running or why it
// failed to start.
func (e *Engine) StreamStatuses() []StreamStatus { return e.streams.Statuses() }

// ReservedPorts lists the ports the proxy engine itself occupies, so stream
// validation can refuse them.
func (e *Engine) ReservedPorts() []int {
	var out []int
	for _, addr := range []string{e.cfg.HTTPAddr, e.cfg.HTTPSAddr} {
		if p := portOf(addr); p > 0 {
			out = append(out, p)
		}
	}
	// The WireGuard port is UDP; a stream may not take it on either protocol,
	// which costs nothing and keeps the rule simple.
	if p := e.wgPort(); p > 0 {
		out = append(out, p)
	}
	return out
}

// CertStatus reports the state of the managed certificate for one domain.
type CertStatus struct {
	Domain    string `json:"domain"`
	Status    string `json:"status"` // issued | pending | failed
	NotAfter  string `json:"notAfter,omitempty"`
	LastError string `json:"lastError,omitempty"`
	ErrorAt   string `json:"errorAt,omitempty"`
}

// NotifyTest sends a test message to the configured webhook.
func (e *Engine) NotifyTest() { e.certs.SendTest() }

// EffectiveRoute summarizes one active route for the "applied config" viewer.
type EffectiveRoute struct {
	Domain   string   `json:"domain"`
	Type     string   `json:"type"`
	Target   string   `json:"target"`
	Wildcard bool     `json:"wildcard"`
	Warnings []string `json:"warnings,omitempty"` // parts of this route that fail closed
}

// EffectiveConfig returns what the engine is actually serving right now,
// proving stored config == applied config (no drift by construction).
func (e *Engine) EffectiveConfig() []EffectiveRoute {
	t := e.table.Load()
	var out []EffectiveRoute
	summ := func(domain string, r *route, wildcard bool) EffectiveRoute {
		er := EffectiveRoute{Domain: domain, Type: r.host.Type, Wildcard: wildcard, Warnings: r.warnings}
		switch r.host.Type {
		case "proxy":
			er.Target = fmt.Sprintf("%s://%s:%d", r.host.Upstream.Scheme, r.host.Upstream.Host, r.host.Upstream.Port)
			if len(r.host.Upstreams) > 0 {
				er.Target += fmt.Sprintf(" (+%d pool)", len(r.host.Upstreams))
			}
		case "redirect":
			if r.host.Redirect != nil {
				er.Target = fmt.Sprintf("%d -> %s", r.host.Redirect.HTTPCode, r.host.Redirect.TargetHost)
			}
		case "static":
			er.Target = r.host.StaticRoot
		}
		return er
	}
	for d, r := range t.exact {
		out = append(out, summ(d, r, false))
	}
	for d, r := range t.wildcard {
		out = append(out, summ("*."+d, r, true))
	}
	return out
}

// banConfig reads the auto-ban settings from the store (at reload).
func (e *Engine) banConfig() banConfig {
	atoi := func(key string, def int) int {
		var n int
		if _, err := fmt.Sscanf(e.store.GetSetting(key, ""), "%d", &n); err == nil && n > 0 {
			return n
		}
		return def
	}
	// The admin API refuses a list with a bad entry, so this only fails on a
	// database edited by hand; the entries before the bad one still count.
	exempt, err := ParseBanExempt(e.store.GetSetting("ban_exempt", ""))
	if err != nil {
		log.Printf("ban: never-ban list: %v", err)
	}
	return banConfig{
		enabled:   e.store.GetSetting("ban_enabled", "") == "1",
		threshold: atoi("ban_threshold", 5),
		window:    time.Duration(atoi("ban_window_sec", 300)) * time.Second,
		banFor:    time.Duration(atoi("ban_duration_sec", 3600)) * time.Second,
		exempt:    exempt,
		exemptOwn: e.store.GetSetting("ban_exempt_own", "") == "1",
	}
}

// publicIdleTimeout is how long the public listeners keep an idle keep-alive
// connection open. A variable so tests can shorten it.
var publicIdleTimeout = 2 * time.Minute

// newPublicServer builds an internet-facing HTTP server. Idle keep-alive
// connections are closed after publicIdleTimeout. There is deliberately no
// read or write timeout for whole requests: uploads and downloads through the
// proxy (container images, backups) can legitimately take a long time.
func newPublicServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{Addr: addr, Handler: h, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: publicIdleTimeout}
}

// CertStatuses inspects certmagic storage for every auto-TLS domain.
func (e *Engine) CertStatuses(ctx context.Context) []CertStatus {
	t := e.table.Load()
	var out []CertStatus
	seen := map[string]bool{}
	add := func(domain string, host store.Host) {
		if seen[domain] || host.CertMode != "auto" {
			return
		}
		seen[domain] = true
		st := CertStatus{Domain: domain, Status: "pending"}
		if cert, err := e.magic.CacheManagedCertificate(ctx, domain); err == nil && cert.Leaf != nil {
			st.Status = "issued"
			st.NotAfter = cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
		}
		if ev, ok := e.certs.get(domain); ok && !ev.OK {
			if st.Status == "pending" {
				st.Status = "failed"
			}
			st.LastError = firstLine(ev.Error)
			st.ErrorAt = ev.At.UTC().Format(time.RFC3339)
		}
		out = append(out, st)
	}
	for d, r := range t.exact {
		add(d, r.host)
	}
	for d, r := range t.wildcard {
		add("*."+d, r.host)
	}
	return out
}

const errorPage = `<!doctype html><html><head><meta charset="utf-8"><title>%d</title>
<style>body{background:#0e0f13;color:#eef1f4;font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0}
div{text-align:center}h1{font-size:64px;margin:0;color:#a3e635}p{color:#8b97a8}</style></head>
<body><div><h1>%d</h1><p>%s</p></div></body></html>`

func serveDefault404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, errorPage, http.StatusNotFound, http.StatusNotFound, "This address is not served here")
}
