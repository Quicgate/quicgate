package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func refTestACL(t *testing.T, st *Store, name string) int64 {
	t.Helper()
	a := &AccessList{Name: name, Satisfy: "any", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := st.CreateAccessList(a); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func refTestHost(domain string) *Host {
	return &Host{Type: "proxy", Domains: []string{domain}, CertMode: "none", Enabled: true,
		Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}
}

// Q05: an access list cannot be deleted while a path rule still uses it.
func TestDeleteAccessListRefusedForPathRule(t *testing.T) {
	st := openTestStore(t)
	id := refTestACL(t, st, "paths")
	h := refTestHost("path.test")
	h.Options.AuthRules = []AuthRule{{Path: "/private/", Mode: "accessList", AccessListID: &id}}
	if err := st.CreateHost(h); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAccessList(id); err == nil {
		t.Fatal("deleted an access list a path rule still references")
	}
}

// Q05: an access list cannot be deleted while a stream still uses it.
func TestDeleteAccessListRefusedForStream(t *testing.T) {
	st := openTestStore(t)
	id := refTestACL(t, st, "streams")
	s := &Stream{ListenPort: 2222, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 22, AccessListID: &id, Enabled: true}
	if err := st.CreateStream(s, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAccessList(id); err == nil {
		t.Fatal("deleted an access list a stream still references")
	}
}

// Q05/Q07: a certificate cannot be deleted while a stream terminates TLS with it.
func TestDeleteCustomCertRefusedForStream(t *testing.T) {
	st := openTestStore(t)
	c, err := st.GenerateSelfSigned("stream", []string{"stream.test"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	s := &Stream{ListenPort: 4443, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 443, TerminateTLS: true, CertID: &c.ID, Enabled: true}
	if err := st.CreateStream(s, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCustomCert(c.ID); err == nil {
		t.Fatal("deleted a certificate a stream still terminates TLS with")
	}
}

// Q05: the store refuses a provider delete while anything still uses it, so
// every caller gets the rule, not only the admin handler.
func TestDeleteOIDCProviderRefusedWhileReferenced(t *testing.T) {
	st := openTestStore(t)
	p := &OIDCProvider{Name: "idp", Issuer: "https://idp.test", ClientID: "c", ClientSecret: "s"}
	if err := st.CreateOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	h := refTestHost("sso.test")
	h.Options.AuthRules = []AuthRule{{Path: "/admin/", Mode: "oidc", OIDC: &OIDCAuth{ProviderID: p.ID}}}
	if err := st.CreateHost(h); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteOIDCProvider(p.ID); err == nil {
		t.Fatal("deleted a provider a path rule still references")
	}
}

// Q05: dangling references are refused on write by the store itself, which is
// what import and any other non-API writer rely on.
func TestHostWriteRejectsDanglingReferences(t *testing.T) {
	st := openTestStore(t)
	missing := int64(999999)
	cases := map[string]func(*Host){
		"host access list": func(h *Host) { h.AccessListID = &missing },
		"path access list": func(h *Host) {
			h.Options.AuthRules = []AuthRule{{Path: "/p/", Mode: "accessList", AccessListID: &missing}}
		},
		"host provider": func(h *Host) { h.Options.OIDC = &OIDCAuth{ProviderID: missing} },
		"path provider": func(h *Host) {
			h.Options.AuthRules = []AuthRule{{Path: "/p/", Mode: "oidc", OIDC: &OIDCAuth{ProviderID: missing}}}
		},
		"custom certificate": func(h *Host) { h.CertMode, h.CertID = "custom", &missing },
	}
	for name, mutate := range cases {
		h := refTestHost(strings.ReplaceAll(name, " ", "-") + ".test")
		mutate(h)
		if err := st.CreateHost(h); err == nil {
			t.Errorf("%s: a dangling reference was stored", name)
		}
	}
	s := &Stream{ListenPort: 2223, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 22, AccessListID: &missing, Enabled: true}
	if err := st.CreateStream(s, nil); err == nil {
		t.Error("stream: a dangling access list reference was stored")
	}
	s2 := &Stream{ListenPort: 2224, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 22, TerminateTLS: true, CertID: &missing, Enabled: true}
	if err := st.CreateStream(s2, nil); err == nil {
		t.Error("stream: a dangling certificate reference was stored")
	}
}
