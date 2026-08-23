package store

import "testing"

func proxyHost(rules []AuthRule) Host {
	h := Host{Type: "proxy", Domains: []string{"a.test"},
		Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}, Enabled: true}
	h.Options.AuthRules = rules
	return h
}

func TestAuthRuleValidation(t *testing.T) {
	id := int64(1)

	h := proxyHost([]AuthRule{
		{Path: " /public/ ", Mode: "public", Methods: []string{"get", " head "}},
		{Path: "/admin/", Mode: "accessList", AccessListID: &id},
	})
	if err := h.Validate(); err != nil {
		t.Fatalf("valid auth rules rejected: %v", err)
	}
	if got := h.Options.AuthRules[0].Path; got != "/public/" {
		t.Fatalf("path not trimmed: %q", got)
	}
	if got := h.Options.AuthRules[0].Methods; len(got) != 2 || got[0] != "GET" || got[1] != "HEAD" {
		t.Fatalf("methods not normalised: %v", got)
	}

	// A public rule must not keep a stale access-list reference around.
	h = proxyHost([]AuthRule{{Path: "/x", Mode: "public", AccessListID: &id}})
	if err := h.Validate(); err != nil {
		t.Fatalf("public rule rejected: %v", err)
	}
	if h.Options.AuthRules[0].AccessListID != nil {
		t.Fatal("public rule kept an access list reference")
	}

	for name, rules := range map[string][]AuthRule{
		"relative path":       {{Path: "manage/", Mode: "public"}},
		"empty path":          {{Path: "", Mode: "public"}},
		"unknown mode":        {{Path: "/x", Mode: "sso"}},
		"empty mode":          {{Path: "/x", Mode: ""}},
		"list without an id":  {{Path: "/x", Mode: "accessList"}},
		"unknown http method": {{Path: "/x", Mode: "public", Methods: []string{"FETCH"}}},
	} {
		h := proxyHost(rules)
		if err := h.Validate(); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

// forwardAuth mode is only meaningful when the host actually has a forward-auth
// endpoint; otherwise the rule would gate nothing at all.
func TestAuthRuleForwardAuthNeedsEndpoint(t *testing.T) {
	h := proxyHost([]AuthRule{{Path: "/x", Mode: "forwardAuth"}})
	if err := h.Validate(); err == nil {
		t.Fatal("forwardAuth rule without an endpoint should be rejected")
	}

	h = proxyHost([]AuthRule{{Path: "/x", Mode: "forwardAuth"}})
	h.Options.ForwardAuth = &ForwardAuth{URL: "https://auth.example.com/api/verify"}
	if err := h.Validate(); err != nil {
		t.Fatalf("forwardAuth rule with an endpoint rejected: %v", err)
	}
}
