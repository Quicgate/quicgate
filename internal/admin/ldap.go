package admin

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ldapAuth is an additive fallback: when local password auth fails and LDAP
// is enabled, try binding to the directory. Never the only path, so a broken
// LDAP config cannot lock out the local admin.
//
// A successful bind proves the directory knows the password; it does not say
// this person should administer the proxy. Callers must still check that the
// identity is approved (ldapIdentityApproved), otherwise every account in a
// corporate directory would hold root over the ingress.
func (s *Server) ldapAuth(username, password string) bool {
	if s.store.GetSetting("ldap_enabled", "") != "1" {
		return false
	}
	url := strings.TrimSpace(s.store.GetSetting("ldap_url", "")) // ldaps://host:636
	bindDN := s.store.GetSetting("ldap_bind_dn_template", "")    // e.g. "uid=%s,ou=people,dc=example,dc=com"
	if url == "" || bindDN == "" || password == "" {
		return false
	}
	// A plain ldap:// bind puts the admin password on the wire in clear text.
	if !strings.HasPrefix(strings.ToLower(url), "ldaps://") {
		log.Printf("ldap: refusing to bind over %q, use ldaps://", url)
		return false
	}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	// The username is substituted into a distinguished name, so it needs DN
	// escaping. EscapeFilter (used previously) escapes search-filter
	// metacharacters and leaves ',', '=', '+' and friends alone, which lets a
	// crafted username rewrite the DN it is spliced into.
	dn := strings.ReplaceAll(bindDN, "%s", ldap.EscapeDN(username))
	return conn.Bind(dn, password) == nil
}

// ldapIdentityApproved reports whether a directory identity may administer
// quicgate: it needs a local account with the same name, or an explicit entry
// in the LDAP allow-list. Authentication answers "who", this answers "may".
func (s *Server) ldapIdentityApproved(username string) bool {
	if _, err := s.store.GetUserByEmail(username); err == nil {
		return true
	}
	return emailAllowed(username, s.store.GetSetting("ldap_allowed_users", ""))
}

// ldapConfigured reports whether LDAP is on, for surfacing in the UI.
func (s *Server) ldapConfigured() bool {
	return s.store.GetSetting("ldap_enabled", "") == "1"
}
