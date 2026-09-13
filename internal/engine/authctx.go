package engine

import (
	"context"
	"net/http"
)

// requestAuth records facts about one request's authentication that later
// middleware can erase, for the layers that run after the gates (the response
// cache): whether the client sent an Authorization header when the request
// arrived, which an access list may have stripped since, and whether a gate
// admitted the request on the strength of an identity rather than its address.
type requestAuth struct {
	hadAuthorization bool
	identified       bool
}

type requestAuthKey struct{}

// withRequestAuth attaches a fresh record to r. It runs outermost on every host,
// before any gate can touch the headers.
func withRequestAuth(r *http.Request) *http.Request {
	ra := &requestAuth{hadAuthorization: r.Header.Get("Authorization") != ""}
	return r.WithContext(context.WithValue(r.Context(), requestAuthKey{}, ra))
}

func requestAuthOf(r *http.Request) *requestAuth {
	ra, _ := r.Context().Value(requestAuthKey{}).(*requestAuth)
	return ra
}

// markIdentified notes that an authentication gate admitted r by identity (a
// basic-auth user, an SSO session, a forward-auth approval).
func markIdentified(r *http.Request) {
	if ra := requestAuthOf(r); ra != nil {
		ra.identified = true
	}
}
