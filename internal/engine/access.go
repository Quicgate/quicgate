package engine

import (
	"net"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

type compiledRule struct {
	allow bool
	net   *net.IPNet
}

type compiledAccess struct {
	name     string
	satisfy  string // any | all
	passAuth bool
	rules    []compiledRule
	users    map[string]string // username -> bcrypt hash
}

func compileAccess(a store.AccessList) *compiledAccess {
	c := &compiledAccess{name: a.Name, satisfy: a.Satisfy, passAuth: a.PassAuth, users: map[string]string{}}
	for _, r := range a.Rules {
		_, ipnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue // validated at save time; defensive
		}
		c.rules = append(c.rules, compiledRule{allow: r.Action == "allow", net: ipnet})
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
	for _, r := range c.rules {
		if r.net.Contains(ip) {
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
