package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"quicgate/internal/seal"
)

// Secrets at rest. These columns hold sealed values (package seal): the three
// settings below, oidc_providers.client_secret, custom_certs.key_pem and
// users.totp_secret. Passwords, basic-auth passwords and API tokens are stored
// as hashes and stay as they are.
//
// A store whose key is missing is LOCKED: it keeps the sealed values as they
// are, opens none of them, replaces none of them, and everything that needs a
// secret fails closed. It never reads a locked secret as "not set".

// secretSettings are the settings whose value is a secret.
var secretSettings = map[string]bool{
	"oidc_client_secret": true, // admin sign-in through OIDC
	"acme_dns_config":    true, // DNS provider credentials for DNS-01
	"sso_cookie_secret":  true, // signs the SSO session cookies
}

// secretColumn is one place a secret lives, for the migration and for unseal.
type secretColumn struct {
	table, column, key string // key: the column that identifies the row
	where              string // optional filter
}

var secretColumns = []secretColumn{
	{table: "settings", column: "value", key: "key", where: "key IN ('oidc_client_secret','acme_dns_config','sso_cookie_secret')"},
	{table: "oidc_providers", column: "client_secret", key: "id"},
	{table: "custom_certs", column: "key_pem", key: "id"},
	{table: "users", column: "totp_secret", key: "id"},
}

// aad names the place a value belongs, so it opens nowhere else.
func aad(table, column string, rowKey any) string {
	return fmt.Sprintf("%s/%s/%v", table, column, rowKey)
}

func settingAAD(key string) string            { return aad("settings", "value", key) }
func providerSecretAAD(id int64) string       { return aad("oidc_providers", "client_secret", id) }
func customCertKeyAAD(id int64) string        { return aad("custom_certs", "key_pem", id) }
func userTOTPAAD(id int64) string             { return aad("users", "totp_secret", id) }
func (c secretColumn) aadFor(k string) string { return aad(c.table, c.column, k) }

// SealStatus describes the state of the secrets for the UI and the log.
type SealStatus struct {
	Locked bool   `json:"locked"`           // sealed values exist that cannot be opened
	Reason string `json:"reason,omitempty"` // why, when locked
	Source string `json:"source,omitempty"` // where the key came from
	KeyID  string `json:"keyId,omitempty"`
}

// SealStatus reports whether the secrets can be opened.
func (s *Store) SealStatus() SealStatus {
	st := SealStatus{Locked: s.lockReason != "", Reason: s.lockReason}
	if s.box.Usable() {
		st.Source, st.KeyID = s.box.Source(), s.box.PrimaryID()
	}
	return st
}

// sealedKeyIDs lists the key ids found in sealed values.
func (s *Store) sealedKeyIDs() (map[string]bool, error) {
	ids := map[string]bool{}
	for _, c := range secretColumns {
		q := "SELECT " + c.column + " FROM " + c.table + " WHERE " + c.column + " LIKE 'qgs1.%'"
		if c.where != "" {
			q += " AND " + c.where
		}
		rows, err := s.db.Query(q)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return nil, err
			}
			if parts := strings.SplitN(v, ".", 3); len(parts) == 3 {
				ids[parts[1]] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// initSeal loads the key and seals what is still in plaintext. It never
// fails the start: without a usable key the store is locked.
func (s *Store) initSeal(dataDir string) {
	ids, err := s.sealedKeyIDs()
	if err != nil {
		s.lockReason = "cannot inspect the stored secrets: " + err.Error()
		log.Printf("seal: %s", s.lockReason)
		return
	}
	box, err := seal.Load(dataDir, len(ids) == 0)
	if err != nil {
		s.lockReason = err.Error()
		log.Printf("seal: LOCKED, %v. Stored secrets are kept as they are and nothing that needs them will work (OIDC sign-in, DNS-01, custom certificates, two-factor logins) until the key is back.", err)
		return
	}
	if len(ids) > 0 {
		opens := false
		for id := range ids {
			if box.HasKey(id) {
				opens = true
			}
		}
		if !opens {
			s.lockReason = "the configured key (" + box.PrimaryID() + ", from " + box.Source() + ") is not the key that sealed the stored secrets"
			log.Printf("seal: LOCKED, %s. Nothing is replaced; restore the right key.", s.lockReason)
			return
		}
	}
	s.box = box
	n, err := s.sealExisting()
	if err != nil {
		log.Printf("seal: sealing the stored secrets failed, they stay as they were: %v", err)
		return
	}
	if n > 0 {
		log.Printf("seal: sealed %d stored secrets with key %s (%s)", n, box.PrimaryID(), box.Source())
		s.scrub()
	}
}

// sealExisting seals every secret that is in plaintext or under an older key,
// in one transaction. It returns how many values it rewrote.
func (s *Store) sealExisting() (int, error) {
	if !s.box.Usable() {
		return 0, seal.ErrLocked
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, c := range secretColumns {
		todo, err := s.valuesOf(tx, c)
		if err != nil {
			return 0, err
		}
		for k, v := range todo {
			if !s.box.NeedsReseal(v) {
				continue
			}
			plain, err := s.box.Open(v, c.aadFor(k))
			if errors.Is(err, seal.ErrLocked) {
				continue // under a key we do not have: leave it alone
			}
			if err != nil {
				return 0, fmt.Errorf("%s.%s %s: %w", c.table, c.column, k, err)
			}
			sealed, err := s.box.Seal(plain, c.aadFor(k))
			if err != nil {
				return 0, err
			}
			if _, err := tx.Exec("UPDATE "+c.table+" SET "+c.column+"=? WHERE "+c.key+"=?", sealed, k); err != nil {
				return 0, err
			}
			n++
		}
	}
	return n, tx.Commit()
}

// valuesOf reads a secret column as row key -> stored value, skipping empties.
func (s *Store) valuesOf(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, c secretColumn) (map[string]string, error) {
	query := "SELECT " + c.key + ", " + c.column + " FROM " + c.table + " WHERE " + c.column + " <> ''"
	if c.where != "" {
		query += " AND " + c.where
	}
	rows, err := q.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k any
		var v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		switch kk := k.(type) {
		case int64:
			out[strconv.FormatInt(kk, 10)] = v
		case []byte:
			out[string(kk)] = v
		default:
			out[fmt.Sprint(kk)] = v
		}
	}
	return out, rows.Err()
}

// scrub removes what replaced values leave behind in the database file: free
// pages and the write-ahead log still hold the old bytes after an UPDATE.
func (s *Store) scrub() {
	for _, stmt := range []string{"PRAGMA wal_checkpoint(TRUNCATE)", "VACUUM", "PRAGMA wal_checkpoint(TRUNCATE)"} {
		if _, err := s.db.Exec(stmt); err != nil {
			log.Printf("seal: %s failed, old plaintext may remain in the database file: %v", stmt, err)
			return
		}
	}
}

// sealAfterRestore seals what a restored backup brought in as plaintext (a
// backup from before sealing existed) and reports secrets that were sealed
// with a key this instance does not have: those stay as they are, unusable
// until the key is added, and are never replaced.
func (s *Store) sealAfterRestore() []string {
	var warnings []string
	if s.box.Usable() {
		n, err := s.sealExisting()
		if err != nil {
			warnings = append(warnings, "sealing the restored secrets failed: "+err.Error())
		} else if n > 0 {
			s.scrub()
		}
	}
	ids, err := s.sealedKeyIDs()
	if err != nil {
		return append(warnings, "cannot inspect the restored secrets: "+err.Error())
	}
	for id := range ids {
		if !s.box.HasKey(id) {
			warnings = append(warnings, "the backup holds secrets sealed with key "+id+", which this instance does not have: they cannot be used until that key is added to the key file (client secrets, DNS credentials, certificate keys, two-factor secrets)")
		}
	}
	return warnings
}

// Unseal rewrites every sealed value as plaintext, for a rollback to a
// version that cannot read sealed values. It needs the key.
func (s *Store) Unseal() (int, error) {
	if !s.box.Usable() {
		return 0, fmt.Errorf("cannot unseal: %s", s.lockReason)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, c := range secretColumns {
		vals, err := s.valuesOf(tx, c)
		if err != nil {
			return 0, err
		}
		for k, v := range vals {
			if !seal.IsSealed(v) {
				continue
			}
			plain, err := s.box.Open(v, c.aadFor(k))
			if err != nil {
				return 0, fmt.Errorf("%s.%s %s: %w", c.table, c.column, k, err)
			}
			if _, err := tx.Exec("UPDATE "+c.table+" SET "+c.column+"=? WHERE "+c.key+"=?", plain, k); err != nil {
				return 0, err
			}
			n++
		}
	}
	return n, tx.Commit()
}

// openSecret opens a stored value. Plaintext written before sealing existed
// passes through.
func (s *Store) openSecret(stored, place string) (string, error) {
	return s.box.Open(stored, place)
}

// sealSecret seals a value for storage. Storing a non-empty secret in a locked
// store is refused: it could only be written in plaintext.
func (s *Store) sealSecret(plain, place string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if !s.box.Usable() {
		return "", fmt.Errorf("the secret store is locked (%s): a new secret cannot be stored", s.lockReason)
	}
	return s.box.Seal(plain, place)
}
