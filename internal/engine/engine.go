package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
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
	cfg   Config
	store *store.Store
	table atomic.Pointer[routingTable]
	magic *certmagic.Config
	acme  *certmagic.ACMEIssuer
	h3    *http3.Server
}

func New(cfg Config, st *store.Store) *Engine {
	e := &Engine{cfg: cfg, store: st}
	e.table.Store(&routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}})

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return e.magic, nil },
	})
	e.magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.DataDir + "/certs"},
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if r := e.table.Load().lookup(name); r != nil && r.host.Enabled && r.host.CertMode == "auto" {
					return nil
				}
				return fmt.Errorf("host %q is not configured for managed TLS", name)
			},
		},
	})
	ca := certmagic.LetsEncryptProductionCA
	if cfg.ACMEStage {
		ca = certmagic.LetsEncryptStagingCA
	}
	e.acme = certmagic.NewACMEIssuer(e.magic, certmagic.ACMEIssuer{
		CA:     ca,
		Email:  cfg.ACMEEmail,
		Agreed: true,
	})
	e.magic.Issuers = []certmagic.Issuer{e.acme}
	return e
}

// Reload rebuilds the routing table from the store and swaps it in atomically,
// then kicks off cert management for any new domains. No listener restarts.
func (e *Engine) Reload(ctx context.Context) error {
	hosts, err := e.store.ListHosts()
	if err != nil {
		return err
	}
	t := &routingTable{exact: map[string]*route{}, wildcard: map[string]*route{}}
	var managed []string
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		r := buildRoute(h)
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
	if len(managed) > 0 && !e.cfg.DisableTLS {
		if err := e.magic.ManageAsync(ctx, managed); err != nil {
			log.Printf("engine: cert management: %v", err)
		}
	}
	log.Printf("engine: routing table reloaded, %d exact + %d wildcard routes", len(t.exact), len(t.wildcard))
	return nil
}

// buildRoute compiles one host's typed options into a ready http.Handler chain.
func buildRoute(h store.Host) *route {
	o := h.Options
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

	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: flush,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			if o.PreserveHost {
				pr.Out.Host = pr.In.Host
			} else if o.HostOverride != "" {
				pr.Out.Host = o.HostOverride
			}
			applyHeaderRules(pr.Out.Header, o.RequestHeaders, pr.In)
		},
		ModifyResponse: func(resp *http.Response) error {
			applyHeaderRules(resp.Header, o.ResponseHeaders, nil)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy %s -> %s: %v", r.Host, target.Host, err)
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintf(w, errorPage, status, status, http.StatusText(status))
		},
	}

	var handler http.Handler = proxy
	if o.MaxBodyMB > 0 {
		limit := int64(o.MaxBodyMB) << 20
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			inner.ServeHTTP(w, r)
		})
	}
	return &route{host: h, proxy: handler}
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

// serveHTTPS is the shared handler behind the TLS (TCP) and QUIC (UDP) listeners.
func (e *Engine) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	rt := e.table.Load().lookup(r.Host)
	if rt == nil {
		serveDefault404(w)
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
		serveDefault404(w)
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
		if r := e.table.Load().lookup(chi.ServerName); r != nil && r.host.Options.MinTLSVersion == "1.3" {
			c := base.Clone()
			c.GetConfigForClient = nil
			c.MinVersion = tls.VersionTLS13
			return c, nil
		}
		return nil, nil
	}
	return base
}

// Run starts the data-plane listeners and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	if err := e.Reload(ctx); err != nil {
		return err
	}

	httpHandler := e.acme.HTTPChallengeHandler(http.HandlerFunc(e.serveHTTP))
	httpSrv := &http.Server{Addr: e.cfg.HTTPAddr, Handler: httpHandler, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 3)
	go func() { errCh <- fmt.Errorf("http listener: %w", httpSrv.ListenAndServe()) }()
	log.Printf("engine: http listening on %s", e.cfg.HTTPAddr)

	var httpsSrv *http.Server
	if !e.cfg.DisableTLS {
		tlsCfg := e.tlsConfig()
		httpsSrv = &http.Server{
			Addr:              e.cfg.HTTPSAddr,
			Handler:           http.HandlerFunc(e.serveHTTPS),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { errCh <- fmt.Errorf("https listener: %w", httpsSrv.ListenAndServeTLS("", "")) }()

		e.h3 = &http3.Server{
			Addr:      e.cfg.HTTPSAddr,
			Handler:   http.HandlerFunc(e.serveHTTPS),
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
		return nil
	case err := <-errCh:
		return err
	}
}

// CertStatus reports the state of the managed certificate for one domain.
type CertStatus struct {
	Domain   string `json:"domain"`
	Status   string `json:"status"` // issued | pending | none
	NotAfter string `json:"notAfter,omitempty"`
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
