package admin

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ldapAuth is an additive fallback: when local password auth fails and LDAP
// is enabled, try binding to the directory. Never the only path, so a broken
// LDAP config cannot lock out the local admin.
func (s *Server) ldapAuth(username, password string) bool {
	if s.store.GetSetting("ldap_enabled", "") != "1" {
		return false
	}
	url := s.store.GetSetting("ldap_url", "")               // ldap://host:389 or ldaps://host:636
	bindDN := s.store.GetSetting("ldap_bind_dn_template", "") // e.g. "uid=%s,ou=people,dc=example,dc=com"
	if url == "" || bindDN == "" || password == "" {
		return false
	}
	conn, err := ldap.DialURL(url)
	if err != nil {
		return false
	}
	defer conn.Close()
	dn := strings.ReplaceAll(bindDN, "%s", ldap.EscapeFilter(username))
	if err := conn.Bind(dn, password); err != nil {
		return false
	}
	return true
}

// ldapConfigured reports whether LDAP is on, for surfacing in the UI.
func (s *Server) ldapConfigured() bool {
	return s.store.GetSetting("ldap_enabled", "") == "1"
}

