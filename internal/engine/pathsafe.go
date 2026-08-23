package engine

import (
	"net/http"
	"strings"
)

// Path safety. Every auth decision quicgate makes is keyed on the request
// path, and so is every routing decision the upstream makes afterwards. If the
// two disagree about what a path means, the gate is decorative: a request for
//
//	/public/../admin/secret
//
// matches a "public" path rule here, but an upstream that resolves dot
// segments (nginx, Apache, IIS, most frameworks) serves /admin/secret — the
// exact resource the host's access list, forward auth or SSO was protecting.
//
// Rewriting the path instead of rejecting it would be worse: the decoded path
// is not always what should go upstream (an encoded %2F inside a segment is
// meaningful to Gitea and others), so quietly normalising risks breaking real
// traffic. A dot segment in a live request is virtually always an attack or a
// broken client — browsers and curl resolve them before sending — so the safe
// and honest answer is to refuse it.

// hasDotSegment reports whether the decoded path contains a "." or ".."
// segment. Segment-wise comparison keeps legitimate names such as
// /.well-known/acme-challenge/... and /file.tar.gz working.
func hasDotSegment(p string) bool {
	if !strings.Contains(p, ".") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// rejectTraversal is the outermost middleware on every host, so a traversal
// attempt never reaches an auth gate, a path rule, a location or an upstream.
func rejectTraversal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasDotSegment(r.URL.Path) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsTLS reports whether the client's connection is encrypted, honouring
// X-Forwarded-Proto for deployments where TLS terminates on a proxy in front
// of quicgate. Believing the header can only add the Secure cookie flag or
// pick the https redirect scheme, never remove either, so a client that lies
// about it only restricts itself.
func requestIsTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
