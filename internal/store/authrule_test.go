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

func TestOIDCAuthValidation(t *testing.T) {
	h := proxyHost(nil)
	h.Options.OIDC = &OIDCAuth{ProviderID: 1,
		AllowedEmails: []string{" Anna@Example.COM "}, AllowedDomains: []string{"Example.com"},
		AllowedGroups: []string{" admins "}}
	if err := h.Validate(); err != nil {
		t.Fatalf("valid oidc config rejected: %v", err)
	}
	if got := h.Options.OIDC.AllowedEmails[0]; got != "anna@example.com" {
		t.Fatalf("email not normalised: %q", got)
	}
	if got := h.Options.OIDC.AllowedDomains[0]; got != "example.com" {
		t.Fatalf("domain not normalised: %q", got)
	}
	if got := h.Options.OIDC.AllowedGroups[0]; got != "admins" {
		t.Fatalf("group not trimmed: %q", got)
	}

	h = proxyHost(nil)
	h.Options.OIDC = &OIDCAuth{}
	if err := h.Validate(); err == nil {
		t.Fatal("oidc without a provider should be rejected")
	}

	h = proxyHost(nil)
	h.Options.OIDC = &OIDCAuth{ProviderID: 1, AllowedDomains: []string{"user@example.com"}}
	if err := h.Validate(); err == nil {
		t.Fatal("an email in allowedDomains should be rejected")
	}

	// The oidc path-rule mode needs host OIDC configured.
	h = proxyHost([]AuthRule{{Path: "/x", Mode: "oidc"}})
	if err := h.Validate(); err == nil {
		t.Fatal("oidc path rule without host OIDC should be rejected")
	}
	h = proxyHost([]AuthRule{{Path: "/x", Mode: "oidc"}})
	h.Options.OIDC = &OIDCAuth{ProviderID: 1}
	if err := h.Validate(); err != nil {
		t.Fatalf("oidc path rule with host OIDC rejected: %v", err)
	}
}

func TestOIDCProviderValidation(t *testing.T) {
	p := OIDCProvider{Name: " kc ", Issuer: "https://idp.example.com/realms/main/", ClientID: "quicgate"}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid provider rejected: %v", err)
	}
	if p.Issuer != "https://idp.example.com/realms/main" {
		t.Fatalf("issuer not trimmed: %q", p.Issuer)
	}
	if p.GroupsClaim != "groups" || p.SessionHours != 12 {
		t.Fatalf("defaults not applied: claim=%q hours=%d", p.GroupsClaim, p.SessionHours)
	}
	for name, bad := range map[string]OIDCProvider{
		"no name":    {Issuer: "https://x", ClientID: "c"},
		"bad issuer": {Name: "a", Issuer: "idp.example.com", ClientID: "c"},
		"no client":  {Name: "a", Issuer: "https://x"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}
