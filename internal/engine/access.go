package engine

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

type compiledRule struct {
	allow   bool
	net     *net.IPNet      // CIDR or resolved DDNS host
	country string          // GeoIP country code, if this is a country rule
	methods map[string]bool // HTTP verbs this rule applies to; nil = all
	// unresolved marks a configured rule that cannot be evaluated right now: a
	// hostname that does not resolve, or a CIDR that does not parse. It matches
	// nobody when it allows and everybody when it denies, so a failure can only
	// ever narrow access, never widen it.
	unresolved bool
}

type compiledAccess struct {
	name     string
	satisfy  string // any | all
	passAuth bool
	rules    []compiledRule
	// restricted reports whether the list configures any network rule (CIDR,
	// hostname or country). Only a list with none is unrestricted by address; a
	// list whose rules all failed to resolve is still restricted.
	restricted bool
	// denyAll closes the list entirely. It stands in for a reference to an
	// access list that no longer exists.
	denyAll  bool
	users    map[string]string // username -> bcrypt hash
	geo      *geoDB
	ban      *banManager
	warnings []string // problems found while compiling, surfaced to the operator
}

// deniedAccess is the gate used when a host or path names an access list that
// does not exist: every request is refused.
func deniedAccess(name string) *compiledAccess {
	return &compiledAccess{name: name, restricted: true, denyAll: true, users: map[string]string{},
		warnings: []string{name + ": the access list no longer exists, so every request is refused"}}
}

// dnsLastKnownGoodMaxAge bounds how long a hostname rule keeps the addresses of
// its last successful lookup while DNS is failing. Past that the rule is
// unresolved and closes.
const dnsLastKnownGoodMaxAge = 24 * time.Hour

// dnsCache resolves access-list hostnames and remembers the last good answer,
// so a DNS outage during a periodic reload keeps the rule working on known
// addresses instead of dropping it.
type dnsCache struct {
	mu      sync.Mutex
	lookup  func(host string) ([]net.IP, error)
	now     func() time.Time
	entries map[string]dnsEntry
}

type dnsEntry struct {
	ips []net.IP
	at  time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{lookup: net.LookupIP, now: time.Now, entries: map[string]dnsEntry{}}
}

var errNoAddresses = errors.New("no addresses")

// resolve returns the addresses for host. When the lookup fails or returns
// nothing it falls back to the last good answer while that is younger than
// dnsLastKnownGoodMaxAge, and reports stale. No addresses means unresolved. A
// nil cache resolves without memory.
func (d *dnsCache) resolve(host string) (ips []net.IP, stale bool, err error) {
	lookup := net.LookupIP
	if d != nil {
		lookup = d.lookup
	}
	ips, err = lookup(host)
	if err == nil && len(ips) == 0 {
		err = errNoAddresses
	}
	if d == nil {
		if err != nil {
			return nil, false, err
		}
		return ips, false, nil
	}
	key := strings.ToLower(host)
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		d.entries[key] = dnsEntry{ips: ips, at: now}
		return ips, false, nil
	}
	if e, ok := d.entries[key]; ok {
		if now.Sub(e.at) <= dnsLastKnownGoodMaxAge {
			return e.ips, true, err
		}
		delete(d.entries, key)
	}
	return nil, false, err
}

// compileAccess builds the runtime matcher. Hostname rules are resolved now
// (a periodic reload re-resolves them for dynamic DNS); country rules keep
// the code and match against the GeoIP DB at request time.
func compileAccess(a store.AccessList, geo *geoDB, ban *banManager, dns *dnsCache) *compiledAccess {
	c := &compiledAccess{name: a.Name, satisfy: a.Satisfy, passAuth: a.PassAuth, users: map[string]string{}, geo: geo, ban: ban}
	for _, r := range a.Rules {
		allow := r.Action == "allow"
		var methods map[string]bool
		if len(r.Methods) > 0 {
			methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				methods[strings.ToUpper(m)] = true
			}
		}
		closed := func(why string) {
			c.rules = append(c.rules, compiledRule{allow: allow, unresolved: true, methods: methods})
			effect := "matches nobody"
			if !allow {
				effect = "denies everyone who reaches it"
			}
			c.warnings = append(c.warnings, fmt.Sprintf("access list %q: %s; the rule %s until this is fixed", a.Name, why, effect))
		}
		switch {
		case r.CIDR != "":
			c.restricted = true
			if _, ipnet, err := net.ParseCIDR(r.CIDR); err == nil {
				c.rules = append(c.rules, compiledRule{allow: allow, net: ipnet, methods: methods})
			} else {
				closed(fmt.Sprintf("%q is not a valid CIDR", r.CIDR))
			}
		case r.Host != "":
			c.restricted = true
			ips, stale, err := dns.resolve(r.Host)
			if len(ips) == 0 {
				log.Printf("access %q: cannot resolve %q: %v (rule closed until it resolves)", a.Name, r.Host, err)
				closed(fmt.Sprintf("hostname %s does not resolve (%v)", r.Host, err))
				continue
			}
			if stale {
				log.Printf("access %q: cannot resolve %q: %v; keeping the last resolved addresses", a.Name, r.Host, err)
				c.warnings = append(c.warnings, fmt.Sprintf("access list %q: hostname %s does not resolve (%v); using its last resolved addresses", a.Name, r.Host, err))
			}
			for _, ip := range ips {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				c.rules = append(c.rules, compiledRule{allow: allow, net: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, methods: methods})
			}
		case r.Country != "":
			c.restricted = true
			c.rules = append(c.rules, compiledRule{allow: allow, country: r.Country, methods: methods})
			if !geo.loaded() {
				c.warnings = append(c.warnings, fmt.Sprintf("access list %q: country rules need the GeoIP database, which is not loaded; allow-country rules match nobody and deny-country rules deny everyone who reaches them", a.Name))
			}
		}
	}
	for _, u := range a.Users {
		c.users[u.Username] = u.Hash
	}
	return c
}

// ipAllowed evaluates the ordered rules for the given method; first match
// wins, no match denies. Rules scoped to specific HTTP verbs are skipped when
// the method differs. Only an access list with no network rules at all imposes
// no address restriction.
func (c *compiledAccess) ipAllowed(remoteAddr, method string) bool {
	return c.evaluate(remoteAddr, method, false)
}

// l4Allowed evaluates the list for a raw TCP or UDP connection, which has no
// HTTP method and cannot present credentials. The ordered address, hostname and
// country rules apply exactly as for HTTP. A rule scoped to HTTP methods can
// only narrow access here: its allow never matches and its deny always does. A
// list that needs basic-auth credentials (satisfy all with users, or users and
// no address rules) cannot be satisfied at this layer and admits nobody.
func (c *compiledAccess) l4Allowed(remoteAddr string) bool {
	if len(c.users) > 0 && (c.satisfy != "any" || !c.restricted) {
		return false
	}
	return c.evaluate(remoteAddr, "", true)
}

// l4Warnings explains, for the stream status, why a list may admit fewer
// connections at L4 than the same list admits HTTP requests.
func (c *compiledAccess) l4Warnings() []string {
	out := append([]string(nil), c.warnings...)
	if len(c.users) > 0 && (c.satisfy != "any" || !c.restricted) {
		out = append(out, fmt.Sprintf("access list %q requires basic-auth credentials, which a stream cannot check, so it admits no connection", c.name))
	}
	for _, r := range c.rules {
		if r.methods != nil && r.allow {
			out = append(out, fmt.Sprintf("access list %q has allow rules limited to HTTP methods; streams ignore those allows", c.name))
			break
		}
	}
	return out
}

func (c *compiledAccess) evaluate(remoteAddr, method string, l4 bool) bool {
	if c.denyAll {
		return false
	}
	if !c.restricted {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	var country string
	looked := false
	for _, r := range c.rules {
		if r.methods != nil {
			if l4 {
				// No method to match: a scoped allow cannot open a connection,
				// a scoped deny still closes it.
				if r.allow {
					continue
				}
			} else if !r.methods[method] {
				continue
			}
		}
		if r.unresolved {
			if r.allow {
				continue
			}
			return false
		}
		if r.country != "" {
			// Without the database a country cannot be known, so the rule is
			// treated like an unresolved one: it never opens anything.
			if !c.geo.loaded() {
				if r.allow {
					continue
				}
				return false
			}
			if !looked {
				country, looked = c.geo.country(ip), true
			}
			if country == r.country {
				return r.allow
			}
			continue
		}
		if r.net != nil && r.net.Contains(ip) {
			return r.allow
		}
	}
	return false
}

func (c *compiledAccess) authOK(r *http.Request) bool {
	if len(c.users) == 0 {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, exists := c.users[user]
	if !exists {
		// Constant-ish cost for unknown users so probing is not cheap.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvali"), []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

// isCORSPreflight reports whether r is a browser CORS preflight. Preflights
// carry no credentials by spec, so gating them behind auth breaks every
// cross-origin app: credential checks let them through and gate the real
// request that follows. Network rules still apply to them.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// wrap gates next behind the access list, mirroring NPM's satisfy semantics.
func (c *compiledAccess) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCORSPreflight(r) {
			// The credential half of the list cannot apply to a preflight; the
			// network half can, for the method the real request will use. When
			// credentials alone could admit that request (satisfy any), its
			// preflight passes wherever it comes from.
			announced := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
			if c.ipAllowed(r.RemoteAddr, announced) || (c.satisfy == "any" && c.restricted && len(c.users) > 0 && !c.denyAll) {
				next.ServeHTTP(w, r)
				return
			}
			if c.ban != nil {
				c.ban.recordFailure(r.RemoteAddr)
			}
			markBlocked(w, blockAccessList)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ipOK := c.ipAllowed(r.RemoteAddr, r.Method)
		authOK := c.authOK(r)
		allowed := ipOK && authOK
		if c.satisfy == "any" && c.restricted && len(c.users) > 0 {
			allowed = ipOK || authOK
		}
		if !allowed {
			if c.ban != nil {
				c.ban.recordFailure(r.RemoteAddr)
			}
			// The first 401 a client without credentials gets is a login prompt
			// (git and Docker always ask that way), not a refusal, as long as
			// credentials could still admit it.
			challenge := r.Header.Get("Authorization") == "" && (ipOK || (c.satisfy == "any" && c.restricted))
			if !challenge || len(c.users) == 0 {
				markBlocked(w, blockAccessList)
			}
			if len(c.users) > 0 && !authOK {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+c.name+`"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if len(c.users) > 0 && authOK {
			markIdentified(r)
		}
		// Strip the credential only when this list actually consumed it for
		// basic-auth and the user opted not to pass it on (NPM's "Pass Auth
		// to Host"). A pure IP/CIDR list must never eat the header: backends
		// like Vaultwarden and gitea authenticate with Authorization: Bearer,
		// and deleting it here silently breaks their logins.
		if !c.passAuth && len(c.users) > 0 {
			r.Header.Del("Authorization")
		}
		next.ServeHTTP(w, r)
	})
}
