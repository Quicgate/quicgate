package store

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// CustomCert is a user-uploaded certificate + key. KeyPEM is never serialized
// to API responses (json:"-").
type CustomCert struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	NotAfter string   `json:"notAfter"`
	CertPEM  string   `json:"certPem,omitempty"` // input + engine use; omitted in lists
	KeyPEM   string   `json:"keyPem,omitempty"`  // input only
}

// parseAndValidate checks the keypair and extracts domains + expiry.
func (c *CustomCert) parseAndValidate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("certificate name is required")
	}
	pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		return fmt.Errorf("certificate/key do not form a valid pair: %w", err)
	}
	block, _ := pem.Decode([]byte(c.CertPEM))
	if block == nil {
		return errors.New("certificate PEM is not decodable")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	_ = pair
	c.Domains = leaf.DNSNames
	if len(c.Domains) == 0 && leaf.Subject.CommonName != "" {
		c.Domains = []string{leaf.Subject.CommonName}
	}
	c.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	return nil
}

func (s *Store) migrateCustomCerts() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS custom_certs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  domains TEXT NOT NULL,
  not_after TEXT NOT NULL,
  cert_pem TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  created_at TEXT NOT NULL
)`)
	return err
}

func (s *Store) ListCustomCerts() ([]CustomCert, error) {
	rows, err := s.db.Query("SELECT id, name, domains, not_after FROM custom_certs ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomCert
	for rows.Next() {
		var c CustomCert
		var domains string
		if err := rows.Scan(&c.ID, &c.Name, &domains, &c.NotAfter); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(domains), &c.Domains)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCustomCertPEM returns the cert + key material for the engine.
func (s *Store) GetCustomCertPEM(id int64) (certPEM, keyPEM string, err error) {
	err = s.db.QueryRow("SELECT cert_pem, key_pem FROM custom_certs WHERE id=?", id).Scan(&certPEM, &keyPEM)
	return
}

func (s *Store) CreateCustomCert(c *CustomCert) error {
	if err := c.parseAndValidate(); err != nil {
		return err
	}
	domainsB, _ := json.Marshal(c.Domains)
	domains := string(domainsB)
	res, err := s.db.Exec(
		"INSERT INTO custom_certs (name, domains, not_after, cert_pem, key_pem, created_at) VALUES (?,?,?,?,?,?)",
		c.Name, domains, c.NotAfter, c.CertPEM, c.KeyPEM, now())
	if err != nil {
		return err
	}
	c.ID, err = res.LastInsertId()
	c.CertPEM, c.KeyPEM = "", ""
	return err
}

// UpdateCustomCertPEM replaces the cert/key of an existing entry in place, so
// hosts referencing it keep working (NPM issue: replace without relinking).
func (s *Store) UpdateCustomCertPEM(id int64, c *CustomCert) error {
	if err := c.parseAndValidate(); err != nil {
		return err
	}
	domainsB, _ := json.Marshal(c.Domains)
	domains := string(domainsB)
	res, err := s.db.Exec(
		"UPDATE custom_certs SET name=?, domains=?, not_after=?, cert_pem=?, key_pem=? WHERE id=?",
		c.Name, domains, c.NotAfter, c.CertPEM, c.KeyPEM, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	c.ID = id
	c.CertPEM, c.KeyPEM = "", ""
	return nil
}

// GenerateSelfSigned creates and stores a self-signed cert for the domains,
// for internal / .lan hosts where ACME cannot reach.
func (s *Store) GenerateSelfSigned(name string, domains []string, days int) (*CustomCert, error) {
	if len(domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	if days <= 0 {
		days = 825
	}
	certPEM, keyPEM, err := selfSignedPEM(domains, days)
	if err != nil {
		return nil, err
	}
	c := &CustomCert{Name: name, CertPEM: certPEM, KeyPEM: keyPEM}
	if err := s.CreateCustomCert(c); err != nil {
		return nil, err
	}
	return c, nil
}

// ImportCertFromFile reads a cert and key from disk paths and stores them.
func (s *Store) ImportCertFromFile(name, certPath, keyPath string) (*CustomCert, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	c := &CustomCert{Name: name, CertPEM: string(certBytes), KeyPEM: string(keyBytes)}
	if err := s.CreateCustomCert(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) DeleteCustomCert(id int64) error {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE cert_id=?", id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("certificate is used by %d host(s)", n)
	}
	res, err := s.db.Exec("DELETE FROM custom_certs WHERE id=?", id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
