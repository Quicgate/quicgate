package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Every reference one object makes to another (a host or stream to an access
// list, a certificate or an identity provider) is checked here, on write and on
// delete, so the admin API, import, restore and Docker adoption all enforce the
// same rules. The engine fails closed on a dangling reference, but one should
// never be storable in the first place, and deleting the target of a live
// reference is refused rather than leaving something pointing at nothing.

// dbtx is the query surface the checks need; *sql.DB and *sql.Tx both satisfy
// it, so a multi-object write can run them inside its transaction.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// rowExists reports whether table has a row with id. table is always one of
// this package's own constant table names, never caller input.
func rowExists(q dbtx, table string, id int64) (bool, error) {
	var n int
	if err := q.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE id = ?", id).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func requireRow(q dbtx, table string, id int64, what string) error {
	ok, err := rowExists(q, table, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s %d does not reference an existing %s", refField(table), id, what)
	}
	return nil
}

func refField(table string) string {
	switch table {
	case "access_lists":
		return "accessListId"
	case "custom_certs":
		return "certId"
	case "oidc_providers":
		return "oidc providerId"
	case "wg_sites":
		return "via"
	}
	return table
}

// checkHostRefs verifies every object a host names.
func checkHostRefs(q dbtx, h *Host) error {
	if h.AccessListID != nil {
		if err := requireRow(q, "access_lists", *h.AccessListID, "access list"); err != nil {
			return err
		}
	}
	if h.CertMode == "custom" && h.CertID != nil {
		if err := requireRow(q, "custom_certs", *h.CertID, "certificate"); err != nil {
			return err
		}
	}
	if h.Options.OIDC != nil {
		if err := requireRow(q, "oidc_providers", h.Options.OIDC.ProviderID, "identity provider"); err != nil {
			return err
		}
	}
	if h.Options.Portal != nil {
		if err := requireRow(q, "oidc_providers", h.Options.Portal.ProviderID, "identity provider"); err != nil {
			return err
		}
	}
	for _, via := range h.Vias() {
		if err := requireRow(q, "wg_sites", via, "WireGuard site"); err != nil {
			return err
		}
	}
	// Within one host an address belongs to one place. The same scheme, host
	// and port reached both locally and through a site, or through two sites,
	// would be two machines that the load balancer and the connection pools
	// have to keep apart by more than their address.
	where := map[string]int64{}
	for _, u := range append(append([]Upstream{h.Upstream}, h.Upstreams...), locationUpstreams(h)...) {
		if u.Host == "" {
			continue
		}
		key := fmt.Sprintf("%s://%s:%d", u.Scheme, strings.ToLower(u.Host), u.Port)
		if prev, ok := where[key]; ok && prev != u.Via {
			return fmt.Errorf("%s is used both with and without a WireGuard site, or with two sites, in this host", key)
		}
		where[key] = u.Via
	}
	for _, r := range h.Options.AuthRules {
		if r.AccessListID != nil {
			if err := requireRow(q, "access_lists", *r.AccessListID, "access list"); err != nil {
				return fmt.Errorf("path %s: %w", r.Path, err)
			}
		}
		if r.OIDC != nil {
			if err := requireRow(q, "oidc_providers", r.OIDC.ProviderID, "identity provider"); err != nil {
				return fmt.Errorf("path %s: %w", r.Path, err)
			}
		}
	}
	return nil
}

// checkAccessListRefs verifies what a list's VPN rules name. A rule that
// names nothing never matches, which is safe, and also never what was meant.
func checkAccessListRefs(q dbtx, a *AccessList) error {
	for i, r := range a.Rules {
		if r.VPN == nil {
			continue
		}
		var err error
		switch {
		case r.VPN.Provider > 0:
			err = requireRow(q, "oidc_providers", r.VPN.Provider, "identity provider")
		case r.VPN.Kind == "peer":
			kind, id, _ := strings.Cut(r.VPN.Peer, ":")
			n, _ := strconv.ParseInt(id, 10, 64)
			if kind == "site" {
				err = requireRow(q, "wg_sites", n, "site")
			} else {
				var live int
				if err = q.QueryRow("SELECT COUNT(*) FROM wg_devices WHERE id=? AND revoked_at=''", n).Scan(&live); err == nil && live == 0 {
					err = fmt.Errorf("peer %s does not reference an existing device", r.VPN.Peer)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

// checkStreamRefs verifies every object a stream names.
func checkStreamRefs(q dbtx, st *Stream) error {
	if st.AccessListID != nil {
		if err := requireRow(q, "access_lists", *st.AccessListID, "access list"); err != nil {
			return err
		}
	}
	if st.CertID != nil {
		if err := requireRow(q, "custom_certs", *st.CertID, "certificate"); err != nil {
			return err
		}
	}
	if st.Via > 0 {
		if err := requireRow(q, "wg_sites", st.Via, "WireGuard site"); err != nil {
			return err
		}
	}
	return nil
}

func locationUpstreams(h *Host) []Upstream {
	out := make([]Upstream, 0, len(h.Locations))
	for _, l := range h.Locations {
		out = append(out, l.Upstream)
	}
	return out
}

func hostLabel(h Host) string {
	if len(h.Domains) > 0 {
		return "host " + h.Domains[0]
	}
	return "host " + strconv.FormatInt(h.ID, 10)
}

// inUse builds the refusal for deleting something that is still referenced.
func inUse(what string, users []string) error {
	const show = 5
	list := users
	if len(list) > show {
		list = append(append([]string(nil), list[:show]...), fmt.Sprintf("and %d more", len(users)-show))
	}
	return fmt.Errorf("%s is still used by %s", what, strings.Join(list, ", "))
}

func accessListUsers(q dbtx, id int64) ([]string, error) {
	var users []string
	hosts, err := listHosts(q)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.AccessListID != nil && *h.AccessListID == id {
			users = append(users, hostLabel(h))
		}
		for _, r := range h.Options.AuthRules {
			if r.AccessListID != nil && *r.AccessListID == id {
				users = append(users, hostLabel(h)+" path "+r.Path)
			}
		}
	}
	streams, err := listStreams(q)
	if err != nil {
		return nil, err
	}
	for _, st := range streams {
		if st.AccessListID != nil && *st.AccessListID == id {
			users = append(users, fmt.Sprintf("stream :%d", st.ListenPort))
		}
	}
	return users, nil
}

func customCertUsers(q dbtx, id int64) ([]string, error) {
	var users []string
	hosts, err := listHosts(q)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.CertID != nil && *h.CertID == id {
			users = append(users, hostLabel(h))
		}
	}
	streams, err := listStreams(q)
	if err != nil {
		return nil, err
	}
	for _, st := range streams {
		if st.CertID != nil && *st.CertID == id {
			users = append(users, fmt.Sprintf("stream :%d", st.ListenPort))
		}
	}
	return users, nil
}

func oidcProviderUsers(q dbtx, id int64) ([]string, error) {
	var users []string
	hosts, err := listHosts(q)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.Options.OIDC != nil && h.Options.OIDC.ProviderID == id {
			users = append(users, hostLabel(h))
		}
		if h.Options.Portal != nil && h.Options.Portal.ProviderID == id {
			users = append(users, hostLabel(h)+" (VPN portal)")
		}
		for _, r := range h.Options.AuthRules {
			if r.OIDC != nil && r.OIDC.ProviderID == id {
				users = append(users, hostLabel(h)+" path "+r.Path)
			}
		}
	}
	// The VPN names people by provider and subject: with the provider gone,
	// a policy, a rule or a device would name nobody, or one day somebody else.
	lists, err := listAccessLists(q)
	if err != nil {
		return nil, err
	}
	for _, a := range lists {
		for _, r := range a.Rules {
			if r.VPN != nil && r.VPN.Provider == id {
				users = append(users, "access list "+a.Name)
				break
			}
		}
	}
	prows, err := q.Query("SELECT name, subject FROM vpn_policies")
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var name, subject string
		if err := prows.Scan(&name, &subject); err != nil {
			return nil, err
		}
		var sub VPNSubject
		if json.Unmarshal([]byte(subject), &sub) == nil && sub.Provider == id {
			users = append(users, "VPN policy "+name)
		}
	}
	if err := prows.Err(); err != nil {
		return nil, err
	}
	var devices int
	if err := q.QueryRow("SELECT COUNT(*) FROM wg_devices WHERE provider=? AND revoked_at=''", id).Scan(&devices); err != nil {
		return nil, err
	}
	if devices > 0 {
		users = append(users, fmt.Sprintf("%d VPN devices of its users (revoke them first)", devices))
	}
	var admin string
	err = q.QueryRow("SELECT value FROM settings WHERE key = ?", "admin_oidc_provider_id").Scan(&admin)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if admin == strconv.FormatInt(id, 10) {
		users = append(users, "the admin login")
	}
	return users, nil
}
