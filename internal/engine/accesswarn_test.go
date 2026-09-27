package engine

import (
	"net/http"
	"strings"
	"testing"

	"quicgate/internal/store"
)

// A list with users under "satisfy any" admits a client with valid credentials
// even when a deny rule refuses its address: the credentials are the other way
// in. That is by design and easy to miss, so the list says so in its warnings,
// which the host's effective route shows. A stream cannot take credentials, so
// its deny rules hold and its warnings leave the note out.
func TestSatisfyAnyDenyOverrideIsWarnedAbout(t *testing.T) {
	users := []store.AccessUser{{Username: "u", Password: "p"}}
	denyThenAllow := []store.AccessRule{{Action: "deny", CIDR: "203.0.113.0/24"}, {Action: "allow", CIDR: "0.0.0.0/0"}}
	noted := func(ws []string) bool {
		for _, w := range ws {
			if strings.Contains(w, "its deny rules refuse") {
				return true
			}
		}
		return false
	}

	over := compileAccess(store.AccessList{Name: "any", Satisfy: "any", Rules: denyThenAllow, Users: users}, nil, nil, nil)
	if !noted(over.warnings) {
		t.Fatalf("no note that credentials override the deny rule: %v", over.warnings)
	}
	if noted(over.l4Warnings()) {
		t.Fatalf("the stream warnings carry the note, but a stream cannot take credentials: %v", over.l4Warnings())
	}
	for name, list := range map[string]store.AccessList{
		"satisfy all":  {Name: "all", Satisfy: "all", Rules: denyThenAllow, Users: users},
		"no users":     {Name: "nousers", Satisfy: "any", Rules: denyThenAllow},
		"no deny rule": {Name: "nodeny", Satisfy: "any", Rules: []store.AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}, Users: users},
	} {
		if c := compileAccess(list, nil, nil, nil); noted(c.warnings) {
			t.Errorf("%s: noted although credentials override no deny rule: %v", name, c.warnings)
		}
	}

	// The semantics the note describes, and the note on the host's route.
	e, st := newTestEngine(t)
	up := backend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	id := mustCreateACL(t, st, &store.AccessList{Name: "lan or password", Satisfy: "any", Rules: denyThenAllow, Users: users})
	mustCreateHost(t, st, &store.Host{Type: "proxy", Domains: []string{"over.test"}, Upstream: up, AccessListID: &id})
	reload(t, e)
	denied := "203.0.113.9"
	if rr := req(e, "GET", "over.test", "/", denied, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("denied address without credentials: %d, want a 401 prompt", rr.Code)
	}
	if rr := req(e, "GET", "over.test", "/", denied, map[string]string{"Authorization": basic("u", "p")}); rr.Code != http.StatusOK {
		t.Fatalf("denied address with valid credentials: %d, want 200 (this is what the note is about)", rr.Code)
	}
	found := false
	for _, r := range e.EffectiveConfig() {
		if r.Domain == "over.test" && noted(r.Warnings) {
			found = true
		}
	}
	if !found {
		t.Fatal("the host's effective route does not carry the note")
	}
}
