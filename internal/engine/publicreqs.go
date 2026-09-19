package engine

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// publicRequests knows the requests that are being served on the public
// listeners right now, per route, so that they can be ended when their host
// stops being public.
//
// A reload swaps the routing table, and that only decides about requests that
// have not started. One that is already running (a WebSocket, a long download,
// an event stream) keeps the route it started with for as long as it likes. For
// most changes that is right. It is wrong when the operator has just taken the
// host off the public side, by marking it VPN only, disabling it or deleting
// it: whoever was connected from outside would simply stay connected (QG-03).
//
// Ending a request means cancelling its context. The reverse proxy closes the
// upstream connection of an upgraded request when that happens, which ends
// both directions; an ordinary request is aborted. On HTTP/2 and HTTP/3 that
// resets the one stream and leaves the connection, and what it carries for
// other hosts, alone.
type publicRequests struct {
	mu   sync.Mutex
	next uint64
	// open is keyed by the names of the host a request was served for. A reload
	// makes new route objects every time, and a request may outlive several
	// reloads, so the route it started on is no identity to find it by.
	open map[string]map[uint64]context.CancelFunc
}

func publicKey(rt *route) string { return strings.Join(rt.host.Domains, " ") }

// track registers a public request under its route and returns the request
// with a context that ending it cancels, and what to call when it is over.
func (p *publicRequests) track(rt *route, r *http.Request) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	key := publicKey(rt)
	p.mu.Lock()
	if p.open == nil {
		p.open = map[string]map[uint64]context.CancelFunc{}
	}
	if p.open[key] == nil {
		p.open[key] = map[uint64]context.CancelFunc{}
	}
	p.next++
	id := p.next
	p.open[key][id] = cancel
	p.mu.Unlock()
	return r.WithContext(ctx), func() {
		p.mu.Lock()
		delete(p.open[key], id)
		if len(p.open[key]) == 0 {
			delete(p.open, key)
		}
		p.mu.Unlock()
		cancel()
	}
}

// endNoLongerPublic ends the public requests of every host that is not served
// publicly under all of its names any more: it became VPN only, was disabled,
// deleted, or lost a name.
func (e *Engine) endNoLongerPublic(current *routingTable) {
	public := map[string]bool{}
	for _, routes := range []map[string]*route{current.exact, current.wildcard} {
		for _, rt := range routes {
			if !rt.host.Options.VPNOnly {
				for _, d := range rt.host.Domains {
					public[d] = true
				}
			}
		}
	}
	p := &e.publicReqs
	var cancels []context.CancelFunc
	p.mu.Lock()
	for key, reqs := range p.open {
		for _, d := range strings.Fields(key) {
			if !public[d] {
				for _, cancel := range reqs {
					cancels = append(cancels, cancel)
				}
				delete(p.open, key)
				break
			}
		}
	}
	p.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}
