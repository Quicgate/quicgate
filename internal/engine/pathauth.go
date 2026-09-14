package engine

import (
	"log"
	"net/http"
	"sort"
	"strings"

	"quicgate/internal/store"
)

// Path-scoped authentication. A host's access list and forward auth normally
// gate every request to it; an auth rule swaps that gate for one URL subtree,
// which is how a host behind SSO still answers an unauthenticated licensing
// callback or webhook without a second host entry.
//
// Each rule gets its own middleware chain around the *same* inner handler,
// built once at reload, so a request only costs a path comparison. Rate limits,
// bot and exploit filters stay host-wide: they are abuse controls, not auth,
// and a public endpoint needs them most.

type pathGate struct {
	path    string
	exact   bool
	methods map[string]bool
	handler http.Handler
}

func (g *pathGate) matches(r *http.Request) bool {
	if len(g.methods) > 0 && !g.methods[r.Method] {
		return false
	}
	if g.exact {
		return r.URL.Path == g.path
	}
	return strings.HasPrefix(r.URL.Path, g.path)
}

type pathAuth struct {
	gates    []pathGate
	fallback http.Handler
	// reserved handles the OIDC callback and logout paths whenever the host
	// has SSO configured, ahead of every rule.
	reserved http.Handler
}

func (p *pathAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.reserved != nil && (r.URL.Path == oidcCallbackPath || r.URL.Path == oidcLogoutPath) {
		p.reserved.ServeHTTP(w, r)
		return
	}
	for i := range p.gates {
		if p.gates[i].matches(r) {
			p.gates[i].handler.ServeHTTP(w, r)
			return
		}
	}
	p.fallback.ServeHTTP(w, r)
}

// closedPath answers every request on a path whose rule names a gate that
// cannot be built (a deleted access list, forward auth or SSO the host does not
// configure, an unknown mode). Falling back to the host's own gate instead
// would open the path whenever the host itself is public.
func closedPath(host []string, rule store.AuthRule, why string) http.Handler {
	log.Printf("engine: host %v path %q: %s; the path is closed", host, rule.Path, why)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		markBlocked(w, blockAccessList)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// buildPathAuth compiles the rules into gates ordered longest path first, so
// the most specific rule wins regardless of the order they were entered in.
// An exact rule beats a prefix rule of the same length.
//
// A rule whose gate cannot be built closes its path (see closedPath): a dangling
// reference must never open anything. The admin API rejects such a reference on
// write as well. ssoFor builds the gate for a rule that names its own identity
// provider or policy, so one host can send different URLs to different IdPs or
// admit different groups per URL.
func buildPathAuth(domains []string, rules []store.AuthRule, o store.Options, acls map[int64]*compiledAccess, sso *oidcGate, ssoFor func(store.OIDCAuth) *oidcGate, inner, fallback http.Handler) http.Handler {
	gates := make([]pathGate, 0, len(rules))
	for _, r := range rules {
		g := pathGate{path: r.Path, exact: r.Exact}
		if len(r.Methods) > 0 {
			g.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				g.methods[m] = true
			}
		}
		switch r.Mode {
		case "public":
			g.handler = inner
		case "forwardAuth":
			if o.ForwardAuth == nil || o.ForwardAuth.URL == "" {
				g.handler = closedPath(domains, r, "forward auth is not configured on this host")
				break
			}
			g.handler = forwardAuth(o.ForwardAuth, inner)
		case "oidc":
			gate := sso
			if r.OIDC != nil {
				gate = ssoFor(*r.OIDC)
			}
			if gate == nil {
				g.handler = closedPath(domains, r, "single sign-on is not configured for this path")
				break
			}
			g.handler = gate.wrap(inner)
		case "accessList":
			var acl *compiledAccess
			if r.AccessListID != nil {
				acl = acls[*r.AccessListID]
			}
			if acl == nil {
				g.handler = closedPath(domains, r, "its access list does not exist")
				break
			}
			g.handler = acl.wrap(inner)
		default:
			g.handler = closedPath(domains, r, "unknown mode "+r.Mode)
		}
		gates = append(gates, g)
	}
	sort.SliceStable(gates, func(i, j int) bool {
		if len(gates[i].path) != len(gates[j].path) {
			return len(gates[i].path) > len(gates[j].path)
		}
		return gates[i].exact && !gates[j].exact
	})
	pa := &pathAuth{gates: gates, fallback: fallback}
	// The login callback must always reach the OIDC gate. Without this, a host
	// that gates only /admin/ with SSO would send the browser to the IdP and
	// then hand the redirect back to whatever rule matched /.qg/oidc/callback,
	// so the session was never minted and the user looped through login.
	if sso == nil {
		// No host-level SSO, but a rule may still have named a provider: the
		// callback has to be served by one of those gates.
		for _, r := range rules {
			if r.Mode == "oidc" && r.OIDC != nil {
				sso = ssoFor(*r.OIDC)
				break
			}
		}
	}
	if sso != nil {
		pa.reserved = sso.wrap(inner)
	}
	return pa
}
