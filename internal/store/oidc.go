package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// OIDCProvider is a reusable OpenID Connect connection (Keycloak, Entra ID,
// Authentik, ...) that proxy hosts reference for built-in SSO. The provider
// holds only how to talk to the IdP; who is allowed through is decided per
// host (OIDCAuth), since different apps trust different groups.
type OIDCProvider struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"`
	Issuer        string   `json:"issuer"` // discovery base URL, e.g. https://idp/realms/main
	ClientID      string   `json:"clientId"`
	ClientSecret  string   `json:"clientSecret"`
	Scopes        []string `json:"scopes,omitempty"`        // default: openid email profile
	GroupsClaim   string   `json:"groupsClaim,omitempty"`   // ID-token claim holding groups, default "groups"
	SessionHours  int      `json:"sessionHours,omitempty"`  // signed-cookie lifetime, default 12
	SkipTLSVerify bool     `json:"skipTlsVerify,omitempty"` // IdP with an internal/self-signed CA
}

func (p *OIDCProvider) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Issuer = strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
	p.ClientID = strings.TrimSpace(p.ClientID)
	if p.Name == "" {
		return errors.New("provider name is required")
	}
	if !strings.HasPrefix(p.Issuer, "http://") && !strings.HasPrefix(p.Issuer, "https://") {
		return errors.New("issuer must be an http(s) URL")
	}
	if p.ClientID == "" {
		return errors.New("client id is required")
	}
	scopes := make([]string, 0, len(p.Scopes))
	for _, s := range p.Scopes {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	p.Scopes = scopes
	if p.GroupsClaim = strings.TrimSpace(p.GroupsClaim); p.GroupsClaim == "" {
		p.GroupsClaim = "groups"
	}
	if p.SessionHours < 0 {
		return errors.New("sessionHours cannot be negative")
	}
	if p.SessionHours == 0 {
		p.SessionHours = 12
	}
	return nil
}

func scanOIDCProvider(row interface{ Scan(...any) error }) (OIDCProvider, error) {
	var p OIDCProvider
	var scopes string
	var skip int
	if err := row.Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.ClientSecret, &scopes, &p.GroupsClaim, &p.SessionHours, &skip); err != nil {
		return p, err
	}
	if scopes != "" {
		p.Scopes = strings.Split(scopes, ",")
	}
	p.SkipTLSVerify = skip == 1
	return p, nil
}

const oidcCols = "id, name, issuer, client_id, client_secret, scopes, groups_claim, session_hours, skip_tls_verify"

func (s *Store) ListOIDCProviders() ([]OIDCProvider, error) {
	rows, err := s.db.Query("SELECT " + oidcCols + " FROM oidc_providers ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OIDCProvider
	for rows.Next() {
		p, err := scanOIDCProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) CreateOIDCProvider(p *OIDCProvider) error {
	if err := p.Validate(); err != nil {
		return err
	}
	res, err := s.db.Exec("INSERT INTO oidc_providers (name, issuer, client_id, client_secret, scopes, groups_claim, session_hours, skip_tls_verify) VALUES (?,?,?,?,?,?,?,?)",
		p.Name, p.Issuer, p.ClientID, p.ClientSecret, strings.Join(p.Scopes, ","), p.GroupsClaim, p.SessionHours, b2i(p.SkipTLSVerify))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateOIDCProvider(p *OIDCProvider) error {
	if err := p.Validate(); err != nil {
		return err
	}
	// An empty secret on update keeps the stored one, so the UI never has to
	// echo the secret back just to save an unrelated field.
	if p.ClientSecret == "" {
		row := s.db.QueryRow("SELECT client_secret FROM oidc_providers WHERE id = ?", p.ID)
		if err := row.Scan(&p.ClientSecret); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return sql.ErrNoRows
			}
			return err
		}
	}
	res, err := s.db.Exec("UPDATE oidc_providers SET name=?, issuer=?, client_id=?, client_secret=?, scopes=?, groups_claim=?, session_hours=?, skip_tls_verify=? WHERE id=?",
		p.Name, p.Issuer, p.ClientID, p.ClientSecret, strings.Join(p.Scopes, ","), p.GroupsClaim, p.SessionHours, b2i(p.SkipTLSVerify), p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteOIDCProvider(id int64) error {
	users, err := oidcProviderUsers(s.db, id)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return inUse("identity provider", users)
	}
	res, err := s.db.Exec("DELETE FROM oidc_providers WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// OIDCAuth gates a proxy host behind quicgate's own OpenID Connect login: the
// engine runs the auth-code flow against the referenced provider, keeps a
// signed per-host session cookie, and optionally passes the identity upstream
// as Remote-User / Remote-Email / Remote-Groups. All three allow-lists empty
// means any authenticated user passes.
type OIDCAuth struct {
	ProviderID     int64    `json:"providerId"`
	AllowedEmails  []string `json:"allowedEmails,omitempty"`  // exact addresses
	AllowedDomains []string `json:"allowedDomains,omitempty"` // e.g. example.com
	AllowedGroups  []string `json:"allowedGroups,omitempty"`  // matched against the groups claim
	PassIdentity   bool     `json:"passIdentity,omitempty"`   // inject Remote-* headers upstream
}

func (o *OIDCAuth) validate() error {
	if o.ProviderID <= 0 {
		return errors.New("oidc: a provider is required")
	}
	norm := func(in []string, lower bool) []string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			v = strings.TrimSpace(v)
			if lower {
				v = strings.ToLower(v)
			}
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	o.AllowedEmails = norm(o.AllowedEmails, true)
	o.AllowedDomains = norm(o.AllowedDomains, true)
	o.AllowedGroups = norm(o.AllowedGroups, false)
	for _, d := range o.AllowedDomains {
		if strings.ContainsAny(d, "@ ") {
			return fmt.Errorf("oidc: %q is not a bare domain", d)
		}
	}
	return nil
}
