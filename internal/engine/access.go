package engine

import (
	"log"
	"net"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

type compiledRule struct {
	allow   bool
	net     *net.IPNet // CIDR or resolved DDNS host
	country string     // GeoIP country code, if this is a country rule
}

type compiledAccess struct {
	name     string
	satisfy  string // any | all
	passAuth bool
	rules    []compiledRule
	users    map[string]string // username -> bcrypt hash
	geo      *geoDB
	ban      *banManager
}

// compileAccess builds the runtime matcher. Hostname rules are resolved now
// (a periodic reload re-resolves them for dynamic DNS); country rules keep
// the code and match against the GeoIP DB at request time.
func compileAccess(a store.AccessList, geo *geoDB, ban *banManager) *compiledAccess {
	c := &compiledAccess{name: a.Name, satisfy: a.Satisfy, passAuth: a.PassAuth, users: map[string]string{}, geo: geo, ban: ban}
	for _, r := range a.Rules {
		allow := r.Action == "allow"
		switch {
		case r.CIDR != "":
			if _, ipnet, err := net.ParseCIDR(r.CIDR); err == nil {
				c.rules = append(c.rules, compiledRule{allow: allow, net: ipnet})
			}
		case r.Host != "":
			ips, err := net.LookupIP(r.Host)
			if err != nil {
				log.Printf("access %q: cannot resolve %q: %v", a.Name, r.Host, err)
				continue
			}
			for _, ip := range ips {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				c.rules = append(c.rules, compiledRule{allow: allow, net: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
			}
		case r.Country != "":
			c.rules = append(c.rules, compiledRule{allow: allow, country: r.Country})
		}
	}
	for _, u := range a.Users {
		c.users[u.Username] = u.Hash
	}
	return c
}

// ipAllowed evaluates the ordered rules; first match wins, no match denies.
// An access list with no IP rules imposes no IP restriction.
func (c *compiledAccess) ipAllowed(remoteAddr string) bool {
	if len(c.rules) == 0 {
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
	for _, r := range c.rules {
		if r.country != "" {
			if country == "" && c.geo != nil {
				country = c.geo.country(ip)
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

// wrap gates next behind the access list, mirroring NPM's satisfy semantics.
func (c *compiledAccess) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipOK := c.ipAllowed(r.RemoteAddr)
		authOK := c.authOK(r)
		allowed := ipOK && authOK
		if c.satisfy == "any" && len(c.rules) > 0 && len(c.users) > 0 {
			allowed = ipOK || authOK
		}
		if !allowed {
			if c.ban != nil {
				c.ban.recordFailure(r.RemoteAddr)
			}
			if len(c.users) > 0 && !authOK {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+c.name+`"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !c.passAuth {
			r.Header.Del("Authorization")
		}
		next.ServeHTTP(w, r)
	})
}
