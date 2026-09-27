package docker

import (
	"fmt"
	"slices"
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
// mapping for that protocol. A host-networked container binds host ports
// directly, so its port is reachable at the address as-is.
type reachPlan struct {
	host       string                        // the Docker host's address
	candidates []int                         // container TCP ports usable for HTTP (before exclude-ports)
	portFor    func(int, string) (int, bool) // maps a container port + protocol to its reachable host port
}

// knownLabels are the keys derive reads, without the prefix. Any other key
// under the prefix is refused: a container that carries quicgate.access_list
// instead of quicgate.access-list asked for a restriction, and publishing it
// without one would be exactly the mistake the label was meant to prevent.
var knownLabels = []string{"enable", "host", "port", "exclude-ports", "scheme", "tls", "tls-skip-verify", "access-list", "streams"}

// unknownLabels lists the container's labels under the prefix that quicgate
// does not know, each with the known key it most likely meant.
func unknownLabels(labels map[string]string, pfx string) []string {
	var keys []string
	for k := range labels {
		if strings.HasPrefix(k, pfx) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		short := k[len(pfx):]
		if slices.Contains(knownLabels, short) {
			continue
		}
		w := "unknown label " + k
		if s := suggestLabel(short); s != "" {
			w += "; did you mean " + pfx + s + "?"
		}
		out = append(out, w)
	}
	return out
}

// suggestLabel names the known key closest to an unknown one, or "" when none
// is close: a different separator or case, or up to two edits away.
func suggestLabel(short string) string {
	norm := strings.ReplaceAll(strings.ToLower(short), "_", "-")
	best, bestDist := "", 3
	for _, k := range knownLabels {
		if d := editDistance(norm, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between two short strings.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
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
	if unknown := unknownLabels(in.Config.Labels, pfx); len(unknown) > 0 {
		d.warnings = append(d.warnings, unknown...)
		d.warnings = append(d.warnings, "the container is not routed while it carries a label quicgate does not know")
		return d
	}
	if !in.State.Running {
		d.warnings = append(d.warnings, "container is not running")
		return d
	}

	plan := resolvePlan(in, address)

	// Optional access list, reused by both the host and the streams. A label
	// that names a list which does not exist means the container is not routed
	// at all: publishing it without the restriction it asked for would let a
	// typo or a deleted list expose the service.
	var aclID *int64
	if al := lbl("access-list"); al != "" {
		id, ok := p.resolveACL(al)
		if !ok {
			d.warnings = append(d.warnings, fmt.Sprintf("access list %q does not exist, so the container is not routed", al))
			return d
		}
		aclID = &id
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
		rport, ok := plan.portFor(cport, "tcp")
		if !ok {
			d.warnings = append(d.warnings, fmt.Sprintf("port %d/tcp is not published on %s (publish it to route)", cport, address))
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
// host's address on the container port's published host port for the protocol
// asked for (Docker publishes 53/tcp and 53/udp separately, and may map them
// to different host ports). A host-networked container binds host ports
// directly, so its container port is reachable as-is on either protocol.
func resolvePlan(in containerInspect, address string) reachPlan {
	published := parsePublished(in.NetworkSettings.Ports)
	var cands []int
	for k := range published {
		if k.proto == "tcp" {
			cands = append(cands, k.port)
		}
	}
	if in.HostConfig.NetworkMode == "host" {
		if exposed := parseExposed(in.Config.ExposedPorts); len(exposed) > 0 {
			cands = exposed
		}
		return reachPlan{host: address, candidates: cands, portFor: func(cp int, _ string) (int, bool) { return cp, true }}
	}
	return reachPlan{host: address, candidates: cands, portFor: func(cp int, proto string) (int, bool) {
		hp, ok := published[portKey{cp, proto}]
		return hp, ok
	}}
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
		// Each protocol has its own publication. A "both" stream forwards
		// both to one host port, so the container must publish them on the
		// same one; sending UDP to the TCP mapping would reach nothing, or
		// something else.
		protos := []string{proto}
		if proto == "both" {
			protos = []string{"tcp", "udp"}
		}
		rport, missing := -1, []string(nil)
		for _, pr := range protos {
			hp, ok := plan.portFor(container, pr)
			switch {
			case !ok:
				missing = append(missing, fmt.Sprintf("%d/%s", container, pr))
			case rport == -1:
				rport = hp
			case hp != rport:
				warns = append(warns, fmt.Sprintf("stream %q: container port %d is published on host port %d for tcp and %d for udp; a both stream forwards both protocols to one port, so publish them on the same host port", part, container, rport, hp))
				rport = -2
			}
		}
		if len(missing) > 0 {
			warns = append(warns, fmt.Sprintf("stream %q: container port %s is not published on %s", part, strings.Join(missing, " and "), plan.host))
			continue
		}
		if rport < 0 {
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

// portKey is a container port on one protocol, the way Docker keys its port
// maps ("53/udp").
type portKey struct {
	port  int
	proto string
}

// parsePortKey parses a Docker port key ("3000/tcp", "53/udp", "443"; no
// protocol means tcp). Only tcp and udp are kept.
func parsePortKey(key string) (portKey, bool) {
	num, proto := key, "tcp"
	if i := strings.IndexByte(key, '/'); i >= 0 {
		num, proto = key[:i], strings.ToLower(key[i+1:])
	}
	if proto != "tcp" && proto != "udp" {
		return portKey{}, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > 65535 {
		return portKey{}, false
	}
	return portKey{n, proto}, true
}

// parseExposed returns the container's declared (EXPOSE) TCP ports: the
// candidates for its HTTP port.
func parseExposed(m map[string]struct{}) []int {
	var out []int
	for k := range m {
		if pk, ok := parsePortKey(k); ok && pk.proto == "tcp" {
			out = append(out, pk.port)
		}
	}
	return out
}

// parsePublished maps each published container port and protocol to its first
// published host port.
func parsePublished(m map[string][]portBinding) map[portKey]int {
	out := map[portKey]int{}
	for k, binds := range m {
		pk, ok := parsePortKey(k)
		if !ok {
			continue
		}
		for _, b := range binds {
			hp, err := strconv.Atoi(b.HostPort)
			if err != nil {
				continue
			}
			if _, exists := out[pk]; !exists {
				out[pk] = hp
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
