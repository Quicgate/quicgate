package store

import (
	"fmt"
	"sort"
	"strings"
)

// ImportDoc is a declarative configuration document, the body of POST
// /api/import.
type ImportDoc struct {
	AccessLists []AccessList `json:"accessLists"`
	Hosts       []Host       `json:"hosts"`
	Streams     []Stream     `json:"streams"`
}

// ImportResult counts what an import created and what it updated in place.
type ImportResult struct {
	Created map[string]int `json:"created"`
	Updated map[string]int `json:"updated"`
}

// Import applies doc in a single transaction: every entry is validated,
// reference-checked and written, or nothing is. Entries are matched to existing
// configuration by a natural key and updated in place rather than duplicated:
// access lists by name, hosts by their set of domains, streams by listen port
// and protocol. Importing the same document twice therefore leaves the
// configuration as the first import did.
//
// An access list's id in the document is the document's own: a host, path rule
// or stream that references it is bound to the list the document defines, under
// whatever id the database assigns. Other references (an access list the
// document does not define, certId, providerId) name existing objects and must
// resolve. A matched entry is never updated in a way that silently removes its
// protection (see protectionRemoved): such a document is refused.
func (s *Store) Import(doc ImportDoc, reserved []int) (ImportResult, error) {
	res := ImportResult{Created: map[string]int{}, Updated: map[string]int{}}
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback() // no-op after a successful commit

	lists, err := listAccessLists(tx)
	if err != nil {
		return res, err
	}
	byName := map[string]AccessList{}
	for _, a := range lists {
		byName[a.Name] = a
	}
	docLists := map[int64]int64{} // access list id in the document -> id in the database
	for i := range doc.AccessLists {
		a := doc.AccessLists[i]
		a.Name = strings.TrimSpace(a.Name)
		docID := a.ID
		if cur, ok := byName[a.Name]; ok {
			if (len(cur.Rules) > 0 || len(cur.Users) > 0) && len(a.Rules) == 0 && len(a.Users) == 0 {
				return res, fmt.Errorf("access list %d (%s): the document has no rules or users for it, so it would admit everyone; change it in the UI or API instead", i+1, a.Name)
			}
			a.ID = cur.ID
			if docID != 0 {
				docLists[docID] = cur.ID
			}
			if err := updateAccessList(tx, &a); err != nil {
				return res, fmt.Errorf("access list %d (%s): %w", i+1, a.Name, err)
			}
			res.Updated["accessLists"]++
			continue
		}
		a.ID = 0
		if err := createAccessList(tx, &a); err != nil {
			return res, fmt.Errorf("access list %d (%s): %w", i+1, a.Name, err)
		}
		byName[a.Name] = a
		if docID != 0 {
			docLists[docID] = a.ID
		}
		res.Created["accessLists"]++
	}
	// local rebinds a reference to an access list the document defines.
	local := func(ref *int64) *int64 {
		if ref == nil {
			return nil
		}
		if id, ok := docLists[*ref]; ok {
			return &id
		}
		return ref
	}

	hosts, err := listHosts(tx)
	if err != nil {
		return res, err
	}
	byDomains := map[string]Host{}
	for _, h := range hosts {
		byDomains[domainKey(h.Domains)] = h
	}
	for i := range doc.Hosts {
		h := doc.Hosts[i]
		h.AccessListID = local(h.AccessListID)
		if len(h.Options.AuthRules) > 0 {
			rules := make([]AuthRule, len(h.Options.AuthRules))
			for j, rule := range h.Options.AuthRules {
				rule.AccessListID = local(rule.AccessListID)
				rules[j] = rule
			}
			h.Options.AuthRules = rules
		}
		key := domainKey(h.Domains)
		if cur, ok := byDomains[key]; ok && key != "" {
			if lost := protectionRemoved(cur, h); lost != "" {
				return res, fmt.Errorf("host %d (%s): the document would remove its %s; include it, or change the host in the UI or API", i+1, key, lost)
			}
			h.ID = cur.ID
			if err := updateHost(tx, &h); err != nil {
				return res, fmt.Errorf("host %d (%s): %w", i+1, key, err)
			}
			res.Updated["hosts"]++
			continue
		}
		h.ID = 0
		if err := createHost(tx, &h); err != nil {
			return res, fmt.Errorf("host %d (%s): %w", i+1, key, err)
		}
		byDomains[domainKey(h.Domains)] = h
		res.Created["hosts"]++
	}

	streams, err := listStreams(tx)
	if err != nil {
		return res, err
	}
	byListen := map[string]Stream{}
	for _, st := range streams {
		byListen[streamKey(st)] = st
	}
	for i := range doc.Streams {
		st := doc.Streams[i]
		st.AccessListID = local(st.AccessListID)
		if st.Protocol == "" {
			st.Protocol = "tcp"
		}
		if cur, ok := byListen[streamKey(st)]; ok {
			if (cur.AccessListID != nil || len(cur.AllowedCIDRs) > 0) && st.AccessListID == nil && len(st.AllowedCIDRs) == 0 {
				return res, fmt.Errorf("stream %d (:%d/%s): the document would remove its source restriction; include it, or change the stream in the UI or API", i+1, st.ListenPort, st.Protocol)
			}
			st.ID = cur.ID
			if err := updateStream(tx, &st, reserved); err != nil {
				return res, fmt.Errorf("stream %d (:%d/%s): %w", i+1, st.ListenPort, st.Protocol, err)
			}
			res.Updated["streams"]++
			continue
		}
		st.ID = 0
		if err := createStream(tx, &st, reserved); err != nil {
			return res, fmt.Errorf("stream %d (:%d/%s): %w", i+1, st.ListenPort, st.Protocol, err)
		}
		byListen[streamKey(st)] = st
		res.Created["streams"]++
	}
	return res, tx.Commit()
}

// protectionRemoved names the protection an import entry would take away from
// the host it updates, or returns "". The document is declarative, but a
// missing field must not quietly make a protected host, or a gated path of it,
// public.
func protectionRemoved(cur, next Host) string {
	switch {
	case cur.AccessListID != nil && next.AccessListID == nil:
		return "access list"
	case cur.Options.OIDC != nil && next.Options.OIDC == nil:
		return "SSO"
	case cur.Options.ForwardAuth != nil && cur.Options.ForwardAuth.URL != "" &&
		(next.Options.ForwardAuth == nil || next.Options.ForwardAuth.URL == ""):
		return "forward authentication"
	case cur.Options.ClientCert != nil && next.Options.ClientCert == nil:
		return "client certificate requirement"
	}
	for _, rule := range cur.Options.AuthRules {
		if rule.Mode == "public" {
			continue
		}
		kept := false
		for _, n := range next.Options.AuthRules {
			if n.Path == rule.Path && n.Exact == rule.Exact && n.Mode != "public" {
				kept = true
				break
			}
		}
		if !kept {
			return rule.Mode + " gate on " + rule.Path
		}
	}
	return ""
}

// domainKey is a host's identity for import matching: its domains, normalised
// the way Host.Validate stores them, sorted.
func domainKey(domains []string) string {
	norm := make([]string, 0, len(domains))
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			norm = append(norm, d)
		}
	}
	sort.Strings(norm)
	return strings.Join(norm, ",")
}

func streamKey(st Stream) string {
	return fmt.Sprintf("%d/%s", st.ListenPort, st.Protocol)
}
