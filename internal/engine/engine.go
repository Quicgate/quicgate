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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/transip"
	"github.com/mholt/acmez/v3"
	"github.com/quic-go/quic-go/http3"

	"quicgate/internal/store"
)

// Config is the engine's static (process-level) configuration.
type Config struct {
	HTTPAddr   string // ":80"
	HTTPSAddr  string // ":443", also the UDP port for HTTP/3
	DataDir    string
	ACMEEmail  string
	ACMEStage  bool // use Let's Encrypt staging CA
	DisableTLS bool // dev mode: no TLS/QUIC listeners at all
	UPnP       bool // request router port forwards via UPnP IGD
}

type route struct {
	host  store.Host
	proxy http.Handler
}

type routingTable struct {
	exact    map[string]*route // "app.example.com"
	wildcard map[string]*route // "example.com" for "*.example.com"
}

func (t *routingTable) lookup(hostport string) *route {
	name := strings.ToLower(hostport)
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
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

	acmeStaging   bool
	acmeEmail     string
	acmeDNS       string
	acmeDNSConfig string
	acmeCAURL     string
	certs         *certTracker
	accessLog     *accessLogger
	health        *healthChecker
	geo           *geoDB
	ban           *banManager
	caPoolCache   sync.Map
}

func New(cfg Config, st *store.Store) *Engine {
	e := &Engine{cfg: cfg, store: st, streams: NewStreamManager(), health: newHealthChecker()}
	e.acmeStaging = cfg.ACMEStage
	e.acmeEmail = cfg.ACMEEmail
	e.certs = newCertTracker(func() string { return st.GetSetting("notify_url", "") })
	e.accessLog = newAccessLogger(cfg.DataDir)
	e.geo = openGeoDB(cfg.DataDir + "/GeoLite2-Country.mmdb")
	e.ban = newBanManager(func() banConfig { return e.banConfig() }, e.certs.send)
	if cfg.UPnP {
		e.upnp = NewUPnPManager(3600)
	}
	e.table.Store(&routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}})

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return e.magic, nil },
	})
	e.magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.DataDir + "/certs"},
		OnEvent: e.certs.handle,
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if r := e.table.Load().lookup(name); r != nil && r.host.Enabled && r.host.CertMode == "auto" {
					return nil
				}
				return fmt.Errorf("host %q is not configured for managed TLS", name)
			},
		},
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
	e.applyACMESettings()
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
		access[a.ID] = compileAccess(a, e.geo, e.ban)
	}
	streams, err := e.store.ListStreams()
	if err != nil {
		return err
	}
	e.loadCustomCerts(hosts)
	t := &routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}}
	healthTargets := map[string]struct{ scheme, hostport string }{}
	var managed []string
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		var acl *compiledAccess
		if h.AccessListID != nil {
			acl = access[*h.AccessListID]
		}
		for _, u := range append([]store.Upstream{h.Upstream}, h.Upstreams...) {
			if u.Host != "" {
				hp := fmt.Sprintf("%s:%d", u.Host, u.Port)
				healthTargets[u.Scheme+"://"+hp] = struct{ scheme, hostport string }{u.Scheme, hp}
			}
		}
		r := e.buildRoute(h, acl)
		for _, d := range h.Domains {
			if strings.HasPrefix(d, "*.") {
				t.wildcard[d[2:]] = r
			} else {
				t.exact[d] = r
			}
			if h.CertMode == "auto" {
				managed = append(managed, d)
			}
		}
	}
	e.table.Store(t)
	e.health.setTargets(healthTargets)
	e.streams.Sync(streams, e.loadStreamCert)
	if e.upnp != nil {
		var mappings []PortMapping
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
		go e.upnp.Sync(mappings)
	}
	if len(managed) > 0 && !e.cfg.DisableTLS {
		if err := e.magic.ManageAsync(ctx, managed); err != nil {
			log.Printf("engine: cert management: %v", err)
		}
	}
	log.Printf("engine: routing table reloaded, %d exact + %d wildcard routes", len(t.exact), len(t.wildcard))
	return nil
}

// loadCustomCerts caches any user-uploaded certificates so the TLS listener
// serves them for their host without ACME. Idempotent across reloads.
func (e *Engine) loadCustomCerts(hosts []store.Host) {
	if e.cfg.DisableTLS {
		return
	}
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
		if _, err := e.magic.CacheUnmanagedCertificatePEMBytes(context.Background(), []byte(certPEM), []byte(keyPEM), nil); err != nil {
			log.Printf("engine: cache custom cert %d: %v", *h.CertID, err)
		}
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

// buildRoute compiles one host's typed options into a ready http.Handler chain.
func (e *Engine) buildRoute(h store.Host, acl *compiledAccess) *route {
	o := h.Options

	// Non-proxy hosts skip the proxy machinery entirely, but still get the
	// access-list, rate-limit and exploit-filter wrappers.
	switch h.Type {
	case "redirect":
		var handler http.Handler = deadHandler()
		if h.Redirect != nil {
			handler = buildRedirectHandler(*h.Redirect)
		}
		return &route{host: h, proxy: wrapCommon(handler, o, acl)}
	case "dead":
		return &route{host: h, proxy: wrapCommon(deadHandler(), o, acl)}
	case "static":
		fs := http.FileServer(http.Dir(h.StaticRoot))
		return &route{host: h, proxy: wrapCommon(fs, o, acl)}
	}

	// Build the balancer target list: primary plus any pool members.
	bal := &balancer{health: e.health}
	pool := append([]store.Upstream{h.Upstream}, h.Upstreams...)
	for _, u := range pool {
		hp := fmt.Sprintf("%s:%d", u.Host, u.Port)
		bal.targets = append(bal.targets, balTarget{
			key: u.Scheme + "://" + hp, url: u.Scheme + "://" + hp, hostport: hp,
		})
	}
	target := &url.URL{Scheme: h.Upstream.Scheme, Host: fmt.Sprintf("%s:%d", h.Upstream.Host, h.Upstream.Port)}

	dialTimeout := 10 * time.Second
	if o.DialTimeoutSec > 0 {
		dialTimeout = time.Duration(o.DialTimeoutSec) * time.Second
	}
	idleTimeout := 90 * time.Second
	if o.IdleTimeoutSec > 0 {
		idleTimeout = time.Duration(o.IdleTimeoutSec) * time.Second
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		IdleConnTimeout:       idleTimeout,
		MaxIdleConnsPerHost:   32,
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
				if u, err := url.Parse(bal.pick()); err == nil {
					pick = u
				}
			}
			pr.SetURL(pick)
			pr.SetXForwarded()
			if rewrite != nil {
				pr.Out.URL.Path = rewrite.apply(pr.Out.URL.Path)
			}
			if o.PreserveHost {
				pr.Out.Host = pr.In.Host
			} else if o.HostOverride != "" {
				pr.Out.Host = o.HostOverride
			}
			applyHeaderRules(pr.Out.Header, o.RequestHeaders, pr.In)
		},
		ModifyResponse: func(resp *http.Response) error {
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
	handler = wrapCommon(handler, o, acl)
	return &route{host: h, proxy: handler}
}

// wrapCommon applies the middleware shared by every host type, outermost
// first: access list -> forward-auth -> rate limit -> bots -> exploit filter.
func wrapCommon(handler http.Handler, o store.Options, acl *compiledAccess) http.Handler {
	if o.BlockExploits {
		handler = blockExploits(handler)
	}
	if o.BlockBadBots {
		handler = blockBadBots(handler)
	}
	if o.RateLimit != nil {
		handler = newRateLimiter(o.RateLimit).wrap(handler)
	}
	if o.ForwardAuth != nil && o.ForwardAuth.URL != "" {
		handler = forwardAuth(o.ForwardAuth, handler)
	}
	if acl != nil {
		handler = acl.wrap(handler)
	}
	return handler
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
func (e *Engine) locationDispatcher(h store.Host, def http.Handler, transport *http.Transport) http.Handler {
	type loc struct {
		prefix string
		proxy  http.Handler
	}
	var locs []loc
	for _, l := range h.Locations {
		target := &url.URL{Scheme: l.Upstream.Scheme, Host: fmt.Sprintf("%s:%d", l.Upstream.Host, l.Upstream.Port)}
		rw := compileRewrite(l.PathRewrite)
		lp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.SetXForwarded()
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
	rt := e.table.Load().lookup(r.Host)
	if rt == nil {
		e.serveUnmatched(w, r)
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
	if e.h3 != nil && (o.HTTP3 == nil || *o.HTTP3) && r.ProtoMajor < 3 {
		if err := e.h3.SetQUICHeaders(w.Header()); err == nil {
			// Alt-Svc set: browsers upgrade to HTTP/3 on the next request.
			_ = err
		}
	}
	rt.proxy.ServeHTTP(w, r)
}

// serveHTTP handles plain port 80: ACME challenges (wrapped outside), the
// force-SSL redirect, and direct serving for certMode "none" hosts.
func (e *Engine) serveHTTP(w http.ResponseWriter, r *http.Request) {
	rt := e.table.Load().lookup(r.Host)
	if rt == nil {
		e.serveUnmatched(w, r)
		return
	}
	if rt.host.ForceSSL {
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
func (e *Engine) tlsConfig() *tls.Config {
	base := e.magic.TLSConfig()
	base.NextProtos = append([]string{"h2", "http/1.1"}, base.NextProtos...)
	base.MinVersion = tls.VersionTLS12
	base.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		r := e.table.Load().lookup(chi.ServerName)
		if r == nil {
			return nil, nil
		}
		o := r.host.Options
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

// clientCAPool parses and caches a PEM CA bundle for mTLS verification.
func (e *Engine) clientCAPool(pemStr string) *x509.CertPool {
	if pemStr == "" {
		return nil
	}
	if v, ok := e.caPoolCache.Load(pemStr); ok {
		return v.(*x509.CertPool)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		log.Printf("engine: mTLS CA bundle did not parse")
		return nil
	}
	e.caPoolCache.Store(pemStr, pool)
	return pool
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

	httpHandler := e.acme.HTTPChallengeHandler(e.ban.wrap(e.accessLog.wrap(e.serveHTTP)))
	httpSrv := &http.Server{Addr: e.cfg.HTTPAddr, Handler: httpHandler, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 3)
	go func() { errCh <- fmt.Errorf("http listener: %w", httpSrv.ListenAndServe()) }()
	log.Printf("engine: http listening on %s", e.cfg.HTTPAddr)

	var httpsSrv *http.Server
	if !e.cfg.DisableTLS {
		tlsCfg := e.tlsConfig()
		httpsHandler := e.ban.wrap(e.accessLog.wrap(e.serveHTTPS))
		httpsSrv = &http.Server{
			Addr:              e.cfg.HTTPSAddr,
			Handler:           httpsHandler,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { errCh <- fmt.Errorf("https listener: %w", httpsSrv.ListenAndServeTLS("", "")) }()

		e.h3 = &http3.Server{
			Addr:      e.cfg.HTTPSAddr,
			Handler:   httpsHandler,
			TLSConfig: http3.ConfigureTLSConfig(tlsCfg),
		}
		go func() { errCh <- fmt.Errorf("http3 listener: %w", e.h3.ListenAndServe()) }()
		log.Printf("engine: https + http/3 listening on %s (tcp+udp)", e.cfg.HTTPSAddr)
	} else {
		log.Printf("engine: TLS disabled (dev mode), only plain http is served")
	}

	select {
	case <-ctx.Done():
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
		if e.upnp != nil {
			e.upnp.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
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

// ReservedPorts lists the ports the proxy engine itself occupies, so stream
// validation can refuse them.
func (e *Engine) ReservedPorts() []int {
	var out []int
	for _, addr := range []string{e.cfg.HTTPAddr, e.cfg.HTTPSAddr} {
		if p := portOf(addr); p > 0 {
			out = append(out, p)
		}
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
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Target   string `json:"target"`
	Wildcard bool   `json:"wildcard"`
}

// EffectiveConfig returns what the engine is actually serving right now,
// proving stored config == applied config (no drift by construction).
func (e *Engine) EffectiveConfig() []EffectiveRoute {
	t := e.table.Load()
	var out []EffectiveRoute
	summ := func(domain string, r *route, wildcard bool) EffectiveRoute {
		er := EffectiveRoute{Domain: domain, Type: r.host.Type, Wildcard: wildcard}
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

// banConfig reads the auto-ban settings live from the store.
func (e *Engine) banConfig() banConfig {
	atoi := func(key string, def int) int {
		var n int
		if _, err := fmt.Sscanf(e.store.GetSetting(key, ""), "%d", &n); err == nil && n > 0 {
			return n
		}
		return def
	}
	return banConfig{
		enabled:   e.store.GetSetting("ban_enabled", "") == "1",
		threshold: atoi("ban_threshold", 5),
		window:    time.Duration(atoi("ban_window_sec", 300)) * time.Second,
		banFor:    time.Duration(atoi("ban_duration_sec", 3600)) * time.Second,
	}
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
