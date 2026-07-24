package docker

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"quicgate/internal/store"
)

// derived is the outcome of interpreting one container's labels.
type derived struct {
	container string
	id        string
	enabled   bool           // the container opted in with quicgate.enable
	host      *store.Host    // the HTTP proxy host, or nil when none/blocked
	streams   []store.Stream // raw L4 forwards from quicgate.streams
	warnings  []string       // human-readable reasons a container is not fully routed
}

// reachPlan describes how quicgate reaches a container's ports. The rule is
// uniform: connect to the Docker host's address on the port's published
// mapping. A host-networked container binds host ports directly, so its port is
// reachable at the address as-is.
type reachPlan struct {
	host       string                // the Docker host's address
	candidates []int                 // container ports usable here (before exclude-ports)
	portFor    func(int) (int, bool) // maps a container port to its reachable host port
}

// derive interprets one container into a proxy host and/or a set of L4 streams.
// address is where this Docker host's published ports are reachable from
// quicgate (127.0.0.1 for the local daemon, the host IP for a remote one).
func (p *Provider) derive(in containerInspect, address string) derived {
	pfx := p.labelPrefix() + "."
	lbl := func(k string) string { return strings.TrimSpace(in.Config.Labels[pfx+k]) }
	d := derived{container: in.name(), id: in.ID}

	if !truthy(lbl("enable")) {
		return d // did not opt in
	}
	d.enabled = true
	if !in.State.Running {
		d.warnings = append(d.warnings, "container is not running")
		return d
	}

	plan := resolvePlan(in, address)

	// Optional access list, reused by both the host and the streams.
	var aclID *int64
	if al := lbl("access-list"); al != "" {
		if id, ok := p.resolveACL(al); ok {
			aclID = &id
		} else {
			d.warnings = append(d.warnings, fmt.Sprintf("access list %q does not exist", al))
		}
	}

	// Raw L4 streams (quicgate.streams). These claim container ports so the
	// HTTP port auto-detection below never picks one of them.
	streams, streamWarns, streamPorts := deriveStreams(lbl("streams"), plan, aclID)
	d.streams = streams
	d.warnings = append(d.warnings, streamWarns...)

	// HTTP proxy host. Candidate ports exclude quicgate.exclude-ports and any
	// port already claimed as a stream.
	exclude := parsePortList(lbl("exclude-ports"))
	for cp := range streamPorts {
		exclude[cp] = true
	}
	domains := splitCSV(lbl("host"))
	if len(domains) == 0 {
		if dom := p.defaultDomain(); dom != "" {
			domains = []string{in.name() + "." + strings.TrimPrefix(dom, ".")}
		}
	}
	explicitPort := lbl("port")
	wantHTTP := lbl("host") != "" || explicitPort != ""
	cport, portWarn := choosePort(plan.candidates, exclude, explicitPort)

	switch {
	case portWarn == "" && len(domains) > 0:
		rport, ok := plan.portFor(cport)
		if !ok {
			d.warnings = append(d.warnings, fmt.Sprintf("port %d is not published on %s (publish it to route)", cport, address))
			break
		}
		h := p.buildHost(lbl, domains, plan.host, rport, aclID)
		if err := h.Validate(); err != nil {
			d.warnings = append(d.warnings, "invalid: "+err.Error())
			break
		}
		d.host = h
	case wantHTTP && portWarn != "":
		d.warnings = append(d.warnings, portWarn)
	case wantHTTP: // explicit HTTP intent but no domain to publish under
		d.warnings = append(d.warnings, "no quicgate.host set and no default-domain configured")
	case len(domains) > 0 && portWarn != "" && len(streams) == 0:
		// default-domain auto-HTTP could not pick a port and there is no stream
		d.warnings = append(d.warnings, portWarn)
	}

	if d.host == nil && len(d.streams) == 0 && len(d.warnings) == 0 {
		d.warnings = append(d.warnings, "quicgate.enable is set but nothing to route (add quicgate.host/quicgate.port or quicgate.streams)")
	}
	return d
}

// resolvePlan resolves how quicgate reaches a container: always the Docker
// host's address on the container port's published host port. A host-networked
// container binds host ports directly, so its container port is reachable as-is.
func resolvePlan(in containerInspect, address string) reachPlan {
	published := parsePublished(in.NetworkSettings.Ports)
	if in.HostConfig.NetworkMode == "host" {
		cands := parseExposed(in.Config.ExposedPorts)
		if len(cands) == 0 {
			for cp := range published {
				cands = append(cands, cp)
			}
		}
		return reachPlan{host: address, candidates: cands, portFor: func(cp int) (int, bool) { return cp, true }}
	}
	var cands []int
	for cp := range published {
		cands = append(cands, cp)
	}
	return reachPlan{host: address, candidates: cands, portFor: func(cp int) (int, bool) { hp, ok := published[cp]; return hp, ok }}
}

// buildHost assembles the proxy host from the resolved upstream and labels.
func (p *Provider) buildHost(lbl func(string) string, domains []string, host string, port int, aclID *int64) *store.Host {
	scheme := "http"
	if strings.EqualFold(lbl("scheme"), "https") {
		scheme = "https"
	}
	h := &store.Host{
		Type:         "proxy",
		Domains:      domains,
		Upstream:     store.Upstream{Scheme: scheme, Host: host, Port: port},
		Enabled:      true,
		Options:      store.Options{SkipTLSVerify: truthy(lbl("tls-skip-verify"))},
		AccessListID: aclID,
	}
	// Public-side TLS: automatic certificate by default; tls=off serves plain
	// HTTP only (no cert, no forced redirect).
	if isOff(lbl("tls")) {
		h.CertMode = "none"
		h.ForceSSL = false
	} else {
		h.CertMode = "auto"
		h.ForceSSL = true
	}
	return h
}

// deriveStreams parses quicgate.streams into L4 forwards. Each entry is
// "[listen:]container[/proto]" (proto tcp|udp|both, default tcp). The listen
// port is what quicgate binds publicly; the forward target is the container's
// reachable address for its container port. Returns the streams, any warnings,
// and the set of container ports claimed (so HTTP auto-detect skips them).
func deriveStreams(spec string, plan reachPlan, aclID *int64) ([]store.Stream, []string, map[int]bool) {
	claimed := map[int]bool{}
	listenSeen := map[int]bool{}
	var streams []store.Stream
	var warns []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		listen, container, proto, err := parseStreamEntry(part)
		if err != nil {
			warns = append(warns, fmt.Sprintf("stream %q: %v", part, err))
			continue
		}
		rport, ok := plan.portFor(container)
		if !ok {
			warns = append(warns, fmt.Sprintf("stream %q: container port %d is not published on %s", part, container, plan.host))
			continue
		}
		if listenSeen[listen] {
			warns = append(warns, fmt.Sprintf("stream %q: listen port %d is used more than once", part, listen))
			continue
		}
		listenSeen[listen] = true
		claimed[container] = true
		streams = append(streams, store.Stream{
			ListenPort:   listen,
			Protocol:     proto,
			ForwardHost:  plan.host,
			ForwardPort:  rport,
			AccessListID: aclID,
			Enabled:      true,
		})
	}
	return streams, warns, claimed
}

// parseStreamEntry parses "[listen:]container[/proto]".
func parseStreamEntry(s string) (listen, container int, proto string, err error) {
	proto = "tcp"
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		proto = strings.ToLower(strings.TrimSpace(s[i+1:]))
		s = s[:i]
	}
	if proto != "tcp" && proto != "udp" && proto != "both" {
		return 0, 0, "", fmt.Errorf("protocol must be tcp, udp or both")
	}
	portOf := func(v string) (int, error) {
		n, e := strconv.Atoi(strings.TrimSpace(v))
		if e != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid port %q", v)
		}
		return n, nil
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if listen, err = portOf(s[:i]); err != nil {
			return 0, 0, "", err
		}
		if container, err = portOf(s[i+1:]); err != nil {
			return 0, 0, "", err
		}
		return listen, container, proto, nil
	}
	if container, err = portOf(s); err != nil {
		return 0, 0, "", err
	}
	return container, container, proto, nil
}

// choosePort resolves which container port to route to: an explicit
// quicgate.port wins; otherwise auto-detect requires exactly one candidate
// after removing excluded ports.
func choosePort(candidates []int, exclude map[int]bool, explicit string) (int, string) {
	if explicit != "" {
		n, err := strconv.Atoi(strings.TrimSpace(explicit))
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Sprintf("invalid quicgate.port %q", explicit)
		}
		return n, ""
	}
	var filtered []int
	for _, c := range candidates {
		if !exclude[c] {
			filtered = append(filtered, c)
		}
	}
	sort.Ints(filtered)
	switch len(filtered) {
	case 0:
		return 0, "no published port to route to (set quicgate.port, or publish the port)"
	case 1:
		return filtered[0], ""
	default:
		return 0, fmt.Sprintf("%d candidate ports %v, set quicgate.port to choose", len(filtered), filtered)
	}
}

// splitCSV splits a comma-separated label value, trimming and dropping blanks.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// The default domain is read live from the store (with the env value as the
// default) so changing it in the UI takes effect on the next reconcile without
// a restart. The label prefix is frozen at startup because it fixes the
// event-stream filter.

func (p *Provider) get(key, def string) string {
	if p.setting == nil {
		return def
	}
	return p.setting(key, def)
}

func (p *Provider) defaultDomain() string {
	return strings.TrimSpace(p.get("docker_default_domain", p.opts.DefaultDomain))
}

func (p *Provider) labelPrefix() string {
	if p.opts.LabelPrefix != "" {
		return p.opts.LabelPrefix
	}
	return "quicgate"
}

// truthy / isOff interpret a boolean-ish label value leniently.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true
	}
	return false
}

func isOff(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "no", "off", "disable", "disabled":
		return true
	}
	return false
}

// tcpPort parses a Docker port key ("3000/tcp") and keeps TCP ports only.
func tcpPort(key string) (int, bool) {
	num, proto := key, "tcp"
	if i := strings.IndexByte(key, '/'); i >= 0 {
		num, proto = key[:i], key[i+1:]
	}
	if proto != "tcp" {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// parseExposed returns the container's declared (EXPOSE) TCP ports.
func parseExposed(m map[string]struct{}) []int {
	var out []int
	for k := range m {
		if p, ok := tcpPort(k); ok {
			out = append(out, p)
		}
	}
	return out
}

// parsePublished maps container TCP port to its first published host port.
func parsePublished(m map[string][]portBinding) map[int]int {
	out := map[int]int{}
	for k, binds := range m {
		cp, ok := tcpPort(k)
		if !ok {
			continue
		}
		for _, b := range binds {
			hp, err := strconv.Atoi(b.HostPort)
			if err != nil {
				continue
			}
			if _, exists := out[cp]; !exists {
				out[cp] = hp
			}
		}
	}
	return out
}

// parsePortList parses a comma-separated port list from a label value.
func parsePortList(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			out[n] = true
		}
	}
	return out
}
