// Package docker turns container labels into quicgate hosts. It watches the
// Docker Engine API over the local socket and, for every container carrying
// quicgate.* labels, derives an in-memory proxy host that the engine merges
// into its routing table alongside the database-backed hosts.
//
// The client here is deliberately tiny: it speaks just enough of the Engine
// API (list, inspect, event stream) over the unix socket to drive the
// provider, using only the standard library. quicgate stays a single small
// binary instead of pulling in the full Docker SDK and its dependency tree.
// Every call is read-only; the provider never creates, starts, or stops a
// container.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a read-only Docker Engine API client over a unix socket.
type Client struct {
	http   *http.Client
	socket string
}

// NewClient returns a client dialing the Docker daemon at socketPath (typically
// /var/run/docker.sock). No client-level timeout is set because the event
// stream is long-lived; list and inspect apply their own per-call deadlines.
func NewClient(socketPath string) *Client {
	return &Client{
		socket: socketPath,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *Client) get(ctx context.Context, path, query string) (*http.Response, error) {
	// The host in the URL is ignored: the transport always dials the socket.
	u := "http://docker" + path
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
