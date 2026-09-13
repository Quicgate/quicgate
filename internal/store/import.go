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
// configuration as the first import did. Ids in the document are ignored, but
// references to existing objects (accessListId, certId, providerId) are kept
// and must resolve.
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
	byName := map[string]int64{}
	for _, a := range lists {
		byName[a.Name] = a.ID
	}
	for i := range doc.AccessLists {
		a := doc.AccessLists[i]
		a.Name = strings.TrimSpace(a.Name)
		if id, ok := byName[a.Name]; ok {
			a.ID = id
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
		byName[a.Name] = a.ID
		res.Created["accessLists"]++
	}

	hosts, err := listHosts(tx)
	if err != nil {
		return res, err
	}
	byDomains := map[string]int64{}
	for _, h := range hosts {
		byDomains[domainKey(h.Domains)] = h.ID
	}
	for i := range doc.Hosts {
		h := doc.Hosts[i]
		key := domainKey(h.Domains)
		if id, ok := byDomains[key]; ok && key != "" {
			h.ID = id
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
		byDomains[domainKey(h.Domains)] = h.ID
		res.Created["hosts"]++
	}

	streams, err := listStreams(tx)
	if err != nil {
		return res, err
	}
	byListen := map[string]int64{}
	for _, st := range streams {
		byListen[streamKey(st)] = st.ID
	}
	for i := range doc.Streams {
		st := doc.Streams[i]
		if st.Protocol == "" {
			st.Protocol = "tcp"
		}
		if id, ok := byListen[streamKey(st)]; ok {
			st.ID = id
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
		byListen[streamKey(st)] = st.ID
		res.Created["streams"]++
	}
	return res, tx.Commit()
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
