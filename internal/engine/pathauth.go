package engine

import (
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
}

func (p *pathAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for i := range p.gates {
		if p.gates[i].matches(r) {
			p.gates[i].handler.ServeHTTP(w, r)
			return
		}
	}
	p.fallback.ServeHTTP(w, r)
}

// buildPathAuth compiles the rules into gates ordered longest path first, so
// the most specific rule wins regardless of the order they were entered in.
// An exact rule beats a prefix rule of the same length.
//
// A rule naming an access list that no longer exists falls back to the host's
// own gate rather than becoming public: a dangling reference must never open a
// path up. The admin API rejects such a reference on write as well.
func buildPathAuth(rules []store.AuthRule, o store.Options, acls map[int64]*compiledAccess, inner, fallback http.Handler) http.Handler {
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
				g.handler = fallback
				break
			}
			g.handler = forwardAuth(o.ForwardAuth, inner)
		case "accessList":
			acl := (*compiledAccess)(nil)
			if r.AccessListID != nil {
				acl = acls[*r.AccessListID]
			}
			if acl == nil {
				g.handler = fallback
				break
			}
			g.handler = acl.wrap(inner)
		default:
			g.handler = fallback
		}
		gates = append(gates, g)
	}
	sort.SliceStable(gates, func(i, j int) bool {
		if len(gates[i].path) != len(gates[j].path) {
			return len(gates[i].path) > len(gates[j].path)
		}
		return gates[i].exact && !gates[j].exact
	})
	return &pathAuth{gates: gates, fallback: fallback}
}
