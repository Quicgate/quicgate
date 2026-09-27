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

// hasAmbiguousSegment reports whether a decoded path holds a construct that
// quicgate's path rules and locations compare as plain text while common
// upstreams read it differently: an empty segment ("//", which nginx and
// Apache merge), a backslash (IIS reads it as "/"), a ";" inside a segment
// (Tomcat and Jetty strip path parameters, so "/..;/" is ".." to them), or a
// "%" left after Go decoded the path once (a double-encoded byte the upstream
// may decode again). "//admin/secret" and "/admin;x/secret" match no rule for
// /admin/ here and reach /admin/secret there.
//
// The case of a path is left alone on purpose: /Admin/ is not /admin/ to
// quicgate, nor to most upstreams, and matching rules regardless of case would
// open every public carve-out to its other spellings on the upstreams that do
// tell them apart. An upstream that ignores case (IIS, a Windows or macOS file
// system) needs its gated paths listed in the spellings it accepts, or a gate
// on the whole host; that is the operator's call, and the docs say so.
func hasAmbiguousSegment(p string) bool {
	return strings.Contains(p, "//") || strings.ContainsAny(p, `\;%`)
}

// rejectAmbiguousPaths refuses a path that hasAmbiguousSegment flags with 400,
// like a dot segment. It guards the path-rule dispatcher (pathauth.go), so only
// a host with path rules pays for it: a host without a path-keyed decision has
// none to get past, and its clients keep such paths. Custom locations are a
// path-keyed decision too; their dispatcher lives in engine.go.
func rejectAmbiguousPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasAmbiguousSegment(r.URL.Path) {
			markBlocked(w, blockExploit)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rejectTraversal is the outermost middleware on every host, so a traversal
// attempt never reaches an auth gate, a path rule, a location or an upstream.
func rejectTraversal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasDotSegment(r.URL.Path) {
			markBlocked(w, blockExploit)
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
