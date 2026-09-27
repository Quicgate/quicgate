package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Endpoint is one Docker daemon quicgate watches.
type Endpoint struct {
	Name    string `json:"name"`    // display name, unique
	Connect string `json:"connect"` // unix socket path, tcp://host:port or https://host:port
	Address string `json:"address"` // where this host's published ports are reachable from quicgate
	// TLS to a remote daemon, Docker's own --tlsverify model: the daemon's
	// certificate must chain to CAFile, and CertFile/KeyFile is the client
	// certificate quicgate presents. Setting any of them makes a tcp://
	// connection TLS; an https:// connection is TLS regardless (with the
	// system roots when no caFile is given). Whoever answers a plaintext
	// tcp:// port defines quicgate's routes, so a daemon reached over the
	// network should be behind these or behind a tunnel.
	CAFile   string `json:"caFile,omitempty"`
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

// tls reports whether the endpoint asks for TLS through its certificate files.
func (e Endpoint) tls() bool { return e.CAFile != "" || e.CertFile != "" || e.KeyFile != "" }

// Validate checks the endpoint's shape: how to connect, where the ports are
// reached, and that the TLS files make sense together. It does not open the
// files; NewClient does, so a missing file shows up as that endpoint's error
// rather than taking the whole list down.
func (e Endpoint) Validate() error {
	if strings.TrimSpace(e.Name) == "" {
		return errors.New("name is required")
	}
	connect := strings.TrimSpace(e.Connect)
	scheme, rest, hasScheme := strings.Cut(connect, "://")
	switch {
	case !hasScheme || scheme == "unix":
		path := connect
		if hasScheme {
			path = rest
		}
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("connect %q must be a unix socket path, tcp://host:port or https://host:port", e.Connect)
		}
		if e.tls() {
			return errors.New("caFile, certFile and keyFile apply to a tcp:// or https:// endpoint, not to a unix socket")
		}
	case scheme == "tcp" || scheme == "http" || scheme == "https":
		if err := validHostPort(rest); err != nil {
			return fmt.Errorf("connect %q: %v", e.Connect, err)
		}
		if scheme == "http" && e.tls() {
			return errors.New("caFile, certFile and keyFile need tcp:// or https://, not http://")
		}
	default:
		return fmt.Errorf("connect %q must be a unix socket path, tcp://host:port or https://host:port", e.Connect)
	}
	if (e.CertFile == "") != (e.KeyFile == "") {
		return errors.New("certFile and keyFile go together")
	}
	if !validHost(strings.TrimSpace(e.Address)) {
		return fmt.Errorf("address %q must be an IP address or a hostname", e.Address)
	}
	return nil
}

// ParseEndpoints decodes the docker_endpoints setting: a JSON list of
// endpoints, nothing else. An unknown field is refused rather than ignored,
// because a misspelt "caFile" would otherwise turn a TLS endpoint into a
// plaintext one without a word. Missing names, connections and addresses take
// the local defaults; every entry is validated and names must be unique.
func ParseEndpoints(raw string) ([]Endpoint, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var eps []Endpoint
	if err := dec.Decode(&eps); err != nil {
		return nil, fmt.Errorf("docker_endpoints: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errors.New("docker_endpoints: text after the list")
	}
	if len(eps) == 0 {
		return nil, errors.New("docker_endpoints: the list is empty")
	}
	names := map[string]bool{}
	for i := range eps {
		ep := &eps[i]
		ep.Name = strings.TrimSpace(ep.Name)
		ep.Connect = strings.TrimSpace(ep.Connect)
		ep.Address = strings.TrimSpace(ep.Address)
		if ep.Connect == "" {
			ep.Connect = "/var/run/docker.sock"
		}
		if ep.Address == "" {
			ep.Address = "127.0.0.1"
		}
		if ep.Name == "" {
			ep.Name = fmt.Sprintf("endpoint%d", i+1)
		}
		if err := ep.Validate(); err != nil {
			return nil, fmt.Errorf("docker_endpoints: entry %d (%s): %w", i+1, ep.Name, err)
		}
		if names[ep.Name] {
			return nil, fmt.Errorf("docker_endpoints: two entries are named %q", ep.Name)
		}
		names[ep.Name] = true
	}
	return eps, nil
}

// validHostPort checks "host:port" (an IPv6 address in brackets) with a port
// in range and a host that is an IP address or a hostname.
func validHostPort(hostport string) error {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return errors.New("need host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port %q is not a number (host:port, nothing after it)", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port %d is out of range", n)
	}
	if !validHost(host) {
		return fmt.Errorf("host %q must be an IP address or a hostname", host)
	}
	return nil
}

// validHost accepts an IP address or a DNS hostname: labels of letters, digits,
// hyphens (and underscores, which Docker's own service names use), each up to
// 63 characters, 253 in all.
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
