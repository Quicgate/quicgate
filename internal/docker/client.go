// Package docker turns container labels into quicgate hosts. It watches the
// Docker Engine API over the local socket, or over the network with TLS and a
// client certificate, and, for every container carrying quicgate.* labels,
// derives an in-memory proxy host that the engine merges into its routing
// table alongside the database-backed hosts.
//
// The client here is deliberately tiny: it speaks just enough of the Engine
// API (list, inspect, event stream) to drive the provider, using only the
// standard library. quicgate stays a single small binary instead of pulling in
// the full Docker SDK and its dependency tree. Every call is read-only; the
// provider never creates, starts, or stops a container.
package docker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client is a read-only Docker Engine API client. It speaks to either a local
// unix socket or a remote endpoint (a read-only socket proxy, or a daemon with
// TLS and client certificates), so quicgate can watch several Docker hosts.
type Client struct {
	http *http.Client
	base string // request base URL; the transport handles the actual dialing
}

// NewClient returns a client for an endpoint's connection:
//   - a bare path or unix:///path  -> local unix socket
//   - tcp://host:port              -> remote, plaintext; TLS when the endpoint
//     names certificate files (Docker's --tlsverify)
//   - http://host:port             -> remote, plaintext
//   - https://host:port            -> remote, TLS (system roots unless caFile)
//
// No client-level timeout is set because the event stream is long-lived; list
// and inspect apply their own per-call deadlines.
func NewClient(ep Endpoint) (*Client, error) {
	base, transport, err := transportFor(ep)
	if err != nil {
		return nil, err
	}
	return &Client{base: base, http: &http.Client{Transport: transport}}, nil
}

// transportFor turns an endpoint into a request base URL and a matching
// transport: a unix dialer for sockets, the default dialer for TCP, and for
// TLS a configuration that verifies the daemon against caFile and presents
// certFile/keyFile. An endpoint that fails Validate is refused here too, so a
// client is never built for a connection string of another shape.
func transportFor(ep Endpoint) (string, *http.Transport, error) {
	if err := ep.Validate(); err != nil {
		return "", nil, err
	}
	connect := strings.TrimSpace(ep.Connect)
	scheme, hostport, hasScheme := strings.Cut(connect, "://")
	if !hasScheme || scheme == "unix" {
		sock := connect
		if hasScheme {
			sock = hostport
		}
		return "http://docker", &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
			},
		}, nil
	}
	useTLS := scheme == "https" || (scheme == "tcp" && ep.tls())
	if !useTLS {
		return "http://" + hostport, &http.Transport{}, nil
	}
	cfg, err := tlsConfigFor(ep)
	if err != nil {
		return "", nil, err
	}
	return "https://" + hostport, &http.Transport{TLSClientConfig: cfg}, nil
}

// tlsConfigFor builds the client TLS configuration from the endpoint's files:
// the daemon must present a certificate chaining to caFile (the system roots
// when none is given), and certFile/keyFile is the client certificate the
// daemon's --tlsverify demands. Verification is never switched off.
func tlsConfigFor(ep Endpoint) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ep.CAFile != "" {
		pemBytes, err := os.ReadFile(ep.CAFile)
		if err != nil {
			return nil, fmt.Errorf("caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("caFile %s holds no CA certificate", ep.CAFile)
		}
		cfg.RootCAs = pool
	}
	if ep.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(ep.CertFile, ep.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("certFile/keyFile: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.RootCAs == nil && len(cfg.Certificates) == 0 && ep.tls() {
		return nil, errors.New("TLS asked for but no usable file given")
	}
	return cfg, nil
}

func (c *Client) get(ctx context.Context, path, query string) (*http.Response, error) {
	// For a unix socket the host in the URL is a placeholder the dialer ignores;
	// for TCP it is the real endpoint.
	u := c.base + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// filtersArg encodes the Engine API's filters query parameter (a JSON object of
// string to string-list) with URL escaping.
func filtersArg(m map[string][]string) string {
	b, _ := json.Marshal(m)
	return "filters=" + url.QueryEscape(string(b))
}

func apiError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		return fmt.Errorf("docker api: %s", resp.Status)
	}
	return fmt.Errorf("docker api %s: %s", resp.Status, msg)
}

// Ping verifies the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := c.get(ctx, "/_ping", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	return nil
}

// containerSummary is the subset of GET /containers/json we use to enumerate
// candidates before inspecting each one.
type containerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

func (s containerSummary) name() string {
	if len(s.Names) > 0 {
		return strings.TrimPrefix(s.Names[0], "/")
	}
	if len(s.ID) > 12 {
		return s.ID[:12]
	}
	return s.ID
}

// List returns running containers carrying the given label key (e.g.
// "quicgate.enable"). The daemon filters server-side so we only pull the
// containers that opted in.
func (c *Client) List(ctx context.Context, labelKey string) ([]containerSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := filtersArg(map[string][]string{"label": {labelKey}})
	resp, err := c.get(ctx, "/containers/json", q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out []containerSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// portBinding is one host-side publication of a container port.
type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// networkEndpoint is a container's attachment to one Docker network.
type networkEndpoint struct {
	IPAddress string `json:"IPAddress"`
}

// containerInspect is the subset of GET /containers/{id}/json the provider
// reads to derive a host: labels, declared ports, published ports, the
// container's network membership + IPs, and its network mode.
type containerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]networkEndpoint `json:"Networks"`
		Ports    map[string][]portBinding   `json:"Ports"`
	} `json:"NetworkSettings"`
}

func (in containerInspect) name() string {
	if n := strings.TrimPrefix(in.Name, "/"); n != "" {
		return n
	}
	if len(in.ID) > 12 {
		return in.ID[:12]
	}
	return in.ID
}

// Inspect returns the full detail for one container.
func (c *Client) Inspect(ctx context.Context, id string) (containerInspect, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out containerInspect
	resp, err := c.get(ctx, "/containers/"+id+"/json", "")
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, apiError(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Event is one container lifecycle event from the daemon's event stream.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

// Events streams container events (filtered to the given label key) into ch
// until ctx is cancelled or the stream fails. It blocks; run it in a goroutine.
func (c *Client) Events(ctx context.Context, labelKey string, ch chan<- Event) error {
	q := filtersArg(map[string][]string{
		"type":  {"container"},
		"label": {labelKey},
	})
	resp, err := c.get(ctx, "/events", q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			return err
		}
		select {
		case ch <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
