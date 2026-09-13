package store

import (
	"strings"
	"testing"
)

// Ids inside an import document refer to the document's own access lists: the
// database assigns new ids on import, so a host that references a list the
// document defines must be bound to that list, never to whatever unrelated
// list happens to have the same id in the target.
func TestImportResolvesDocumentAccessListIDs(t *testing.T) {
	st := openTestStore(t)
	everyone := &AccessList{Name: "everyone", Satisfy: "any", Rules: []AccessRule{{Action: "allow", CIDR: "0.0.0.0/0"}}}
	if err := st.CreateAccessList(everyone); err != nil {
		t.Fatal(err)
	}
	docID := everyone.ID // the document's own id collides with the unrelated list
	hostRef, ruleRef, streamRef := docID, docID, docID
	h := *refTestHost("secret.test")
	h.AccessListID = &hostRef
	h.Options.AuthRules = []AuthRule{{Path: "/admin/", Mode: "accessList", AccessListID: &ruleRef}}
	doc := ImportDoc{
		AccessLists: []AccessList{{ID: docID, Name: "office", Satisfy: "any", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}},
		Hosts:       []Host{h},
		Streams: []Stream{{ListenPort: 40123, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 80,
			AccessListID: &streamRef, Enabled: true}},
	}
	if _, err := st.Import(doc, nil); err != nil {
		t.Fatal(err)
	}
	var office int64
	lists, _ := st.ListAccessLists()
	for _, a := range lists {
		if a.Name == "office" {
			office = a.ID
		}
	}
	if office == 0 || office == everyone.ID {
		t.Fatalf("office list id = %d (everyone is %d)", office, everyone.ID)
	}
	hosts, _ := st.ListHosts()
	if len(hosts) != 1 || hosts[0].AccessListID == nil || *hosts[0].AccessListID != office {
		t.Fatalf("host bound to access list %v, want office (%d)", hosts[0].AccessListID, office)
	}
	if r := hosts[0].Options.AuthRules; len(r) != 1 || r[0].AccessListID == nil || *r[0].AccessListID != office {
		t.Fatalf("path rule bound to %v, want office (%d)", r, office)
	}
	streams, _ := st.ListStreams()
	if len(streams) != 1 || streams[0].AccessListID == nil || *streams[0].AccessListID != office {
		t.Fatalf("stream bound to access list %v, want office (%d)", streams[0].AccessListID, office)
	}
}

// An import that matches existing configuration updates it in place, but it
// never silently removes protection: a document that leaves out a host's
// access list, SSO or path gate, a stream's source restriction, or every rule
// of an access list is refused with a reason, and nothing changes.
func TestImportRefusesToRemoveProtection(t *testing.T) {
	st := openTestStore(t)
	aclID := refTestACL(t, st, "lan")
	prov := &OIDCProvider{Name: "idp", Issuer: "https://idp.example", ClientID: "c"}
	if err := st.CreateOIDCProvider(prov); err != nil {
		t.Fatal(err)
	}
	protected := func() Host {
		h := *refTestHost("vault.test")
		acl := aclID
		h.AccessListID = &acl
		h.Options.OIDC = &OIDCAuth{ProviderID: prov.ID}
		return h
	}
	caPEM := testCAPEM(t)
	edge := func() Host {
		h := *refTestHost("edge.test")
		h.Options.ForwardAuth = &ForwardAuth{URL: "http://127.0.0.1:9/auth"}
		h.CertMode = "auto"
		h.Options.ClientCert = &ClientCert{Mode: "require", CAPEM: caPEM}
		return h
	}
	gated := func() Host {
		h := *refTestHost("paths.test")
		acl := aclID
		h.Options.AuthRules = []AuthRule{{Path: "/admin/", Mode: "accessList", AccessListID: &acl}}
		return h
	}
	vault, paths, edgeHost := protected(), gated(), edge()
	for _, h := range []*Host{&vault, &paths, &edgeHost} {
		if err := st.CreateHost(h); err != nil {
			t.Fatal(err)
		}
	}
	stream := &Stream{ListenPort: 40200, Protocol: "tcp", ForwardHost: "127.0.0.1", ForwardPort: 80,
		AllowedCIDRs: []string{"10.0.0.0/8"}, Enabled: true}
	if err := st.CreateStream(stream, nil); err != nil {
		t.Fatal(err)
	}

	noACL, noSSO, public, noFwd, noCert := protected(), protected(), gated(), edge(), edge()
	noACL.AccessListID = nil
	noSSO.Options.OIDC = nil
	noFwd.Options.ForwardAuth = nil
	noCert.Options.ClientCert = nil
	public.Options.AuthRules = []AuthRule{{Path: "/admin/", Mode: "public"}}
	for name, c := range map[string]struct {
		doc    ImportDoc
		reason string
	}{
		"host without its access list": {ImportDoc{Hosts: []Host{noACL}}, "access list"},
		"host without its SSO":         {ImportDoc{Hosts: []Host{noSSO}}, "SSO"},
		"path gate made public":        {ImportDoc{Hosts: []Host{public}}, "/admin/"},
		"host without forward auth":    {ImportDoc{Hosts: []Host{noFwd}}, "forward authentication"},
		"host without client certs":    {ImportDoc{Hosts: []Host{noCert}}, "client certificate"},
		"stream without its restriction": {ImportDoc{Streams: []Stream{{ListenPort: 40200, Protocol: "tcp",
			ForwardHost: "127.0.0.1", ForwardPort: 80, Enabled: true}}}, "source restriction"},
		"access list without rules or users": {ImportDoc{AccessLists: []AccessList{{Name: "lan", Satisfy: "any"}}}, "admit everyone"},
	} {
		_, err := st.Import(c.doc, nil)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Fatalf("%s: got %v, want a refusal that mentions %q", name, err, c.reason)
		}
	}
	got, err := st.GetHost(vault.ID)
	if err != nil || got.AccessListID == nil || got.Options.OIDC == nil {
		t.Fatalf("host protection changed: %+v %v", got, err)
	}
	if got, _ := st.GetHost(paths.ID); len(got.Options.AuthRules) != 1 || got.Options.AuthRules[0].Mode != "accessList" {
		t.Fatalf("path gate changed: %+v", got.Options.AuthRules)
	}
	streams, _ := st.ListStreams()
	if len(streams) != 1 || len(streams[0].AllowedCIDRs) != 1 {
		t.Fatalf("stream restriction changed: %+v", streams)
	}
	lists, _ := st.ListAccessLists()
	if len(lists) != 1 || len(lists[0].Rules) != 1 {
		t.Fatalf("access list changed: %+v", lists)
	}

	// Keeping the protection, the same document updates the host in place.
	keep := protected()
	keep.Upstream.Port = 9090
	res, err := st.Import(ImportDoc{Hosts: []Host{keep}}, nil)
	if err != nil || res.Updated["hosts"] != 1 {
		t.Fatalf("import that keeps the protection: %+v %v", res, err)
	}
	if got, _ := st.GetHost(vault.ID); got.Upstream.Port != 9090 {
		t.Fatalf("host not updated in place: %+v", got.Upstream)
	}
}
