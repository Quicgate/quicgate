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

// Secrets at rest. These columns hold sealed values (package seal): the four
// settings below, the WireGuard preshared keys, oidc_providers.client_secret,
// custom_certs.key_pem, users.totp_secret and vpn_sessions.refresh_token.
// Passwords, basic-auth passwords and API tokens are stored as hashes and stay
// as they are. Every sealed column is listed in secretColumns: that list is
// what a key rotation re-seals and what -unseal writes back, so a column that
// is sealed by its writer but missing here would stay under a retired key.
//
// A store whose key is missing is LOCKED: it keeps the sealed values as they
// are, opens none of them, replaces none of them, and everything that needs a
// secret fails closed. It never reads a locked secret as "not set".

// secretSettings are the settings whose value is a secret.
var secretSettings = map[string]bool{
	"oidc_client_secret": true, // admin sign-in through OIDC
	"acme_dns_config":    true, // DNS provider credentials for DNS-01
	"sso_cookie_secret":  true, // signs the SSO session cookies
	"wg_private_key":     true, // the WireGuard server key
}

// secretColumn is one place a secret lives, for the migration and for unseal.
type secretColumn struct {
	table, column, key string // key: the column that identifies the row
	where              string // optional filter
	// extra names further columns that are part of the row's place: the
	// writer sealed the value to them as well as to the key (a VPN refresh
	// token is bound to its provider and subject, see sessionTokenAAD), so
	// the migration and unseal must compute the same place.
	extra []string
}

var secretColumns = []secretColumn{
	{table: "settings", column: "value", key: "key", where: "key IN ('oidc_client_secret','acme_dns_config','sso_cookie_secret','wg_private_key')"},
	{table: "wg_sites", column: "psk", key: "id"},
	{table: "wg_devices", column: "psk", key: "id"},
	{table: "oidc_providers", column: "client_secret", key: "id"},
	{table: "custom_certs", column: "key_pem", key: "id"},
	{table: "users", column: "totp_secret", key: "id"},
	{table: "vpn_sessions", column: "refresh_token", key: "id", extra: []string{"provider", "sub"}},
}

// aad names the place a value belongs, so it opens nowhere else.
func aad(table, column string, rowKey any) string {
	return fmt.Sprintf("%s/%s/%v", table, column, rowKey)
}

func settingAAD(key string) string      { return aad("settings", "value", key) }
func providerSecretAAD(id int64) string { return aad("oidc_providers", "client_secret", id) }
func customCertKeyAAD(id int64) string  { return aad("custom_certs", "key_pem", id) }
func userTOTPAAD(id int64) string       { return aad("users", "totp_secret", id) }

// aadFor names the place of one row's value: the key, then the extra columns'
// values, joined with "/" the way the writers join them.
func (c secretColumn) aadFor(k string, extra []string) string {
	return aad(c.table, c.column, strings.Join(append([]string{k}, extra...), "/"))
}

// secretRow is one stored value with the place it is sealed for.
type secretRow struct {
	key   string // the row's key, as text
	value string // the stored value, sealed or plaintext
	place string // the associated data the value is (to be) sealed with
}

// SealStatus describes the state of the secrets for the UI and the log.
type SealStatus struct {
	Locked bool   `json:"locked"`           // sealed values exist that cannot be opened
	Reason string `json:"reason,omitempty"` // why, when locked
	Source string `json:"source,omitempty"` // where the key came from
	KeyID  string `json:"keyId,omitempty"`
	// Warnings name stored values the migration could not seal or re-seal
	// (damaged, or moved from another row): they are kept as they are and
	// cannot be used, while every other secret is sealed.
	Warnings []string `json:"warnings,omitempty"`
}

// SealStatus reports whether the secrets can be opened.
func (s *Store) SealStatus() SealStatus {
	st := SealStatus{Locked: s.lockReason != "", Reason: s.lockReason, Warnings: s.sealWarnings}
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
	n, warnings, err := s.sealExisting()
	if err != nil {
		log.Printf("seal: sealing the stored secrets failed, they stay as they were: %v", err)
		return
	}
	for _, w := range warnings {
		log.Printf("seal: %s: the value is kept as it is and cannot be used", w)
	}
	s.sealWarnings = warnings
	if n > 0 {
		log.Printf("seal: sealed %d stored secrets with key %s (%s)", n, box.PrimaryID(), box.Source())
		s.scrub()
	}
}

// sealExisting seals every secret that is in plaintext or under an older key,
// in one transaction, and returns how many values it rewrote. A value that
// does not open (damaged, or moved from another row) is left as it is and
// named in the warnings, so that one such value does not keep every other
// secret in plaintext while the status says "sealed". A value under a key this
// box does not have is left alone without a word, as before: it is not ours
// to touch. Only a failure of the store itself is an error.
func (s *Store) sealExisting() (int, []string, error) {
	if !s.box.Usable() {
		return 0, nil, seal.ErrLocked
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	n := 0
	var warnings []string
	for _, c := range secretColumns {
		rows, err := s.valuesOf(tx, c)
		if err != nil {
			return 0, nil, err
		}
		for _, r := range rows {
			if !s.box.NeedsReseal(r.value) {
				continue
			}
			plain, err := s.box.Open(r.value, r.place)
			if errors.Is(err, seal.ErrLocked) {
				continue // under a key we do not have: leave it alone
			}
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s.%s %s: %v", c.table, c.column, r.key, err))
				continue
			}
			sealed, err := s.box.Seal(plain, r.place)
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec("UPDATE "+c.table+" SET "+c.column+"=? WHERE "+c.key+"=?", sealed, r.key); err != nil {
				return 0, nil, err
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}
	return n, warnings, nil
}

// valuesOf reads a secret column's non-empty values with their row keys and
// the place each one belongs to.
func (s *Store) valuesOf(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, c secretColumn) ([]secretRow, error) {
	cols := append([]string{c.key, c.column}, c.extra...)
	query := "SELECT " + strings.Join(cols, ", ") + " FROM " + c.table + " WHERE " + c.column + " <> ''"
	if c.where != "" {
		query += " AND " + c.where
	}
	rows, err := q.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []secretRow
	for rows.Next() {
		scanned := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range scanned {
			ptrs[i] = &scanned[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := secretRow{key: columnText(scanned[0]), value: columnText(scanned[1])}
		var extra []string
		for _, v := range scanned[2:] {
			extra = append(extra, columnText(v))
		}
		r.place = c.aadFor(r.key, extra)
		out = append(out, r)
	}
	return out, rows.Err()
}

// columnText renders a scanned column the way the writers render it in the
// associated data: integers in decimal, text as it is.
func columnText(v any) string {
	switch vv := v.(type) {
	case int64:
		return strconv.FormatInt(vv, 10)
	case []byte:
		return string(vv)
	case string:
		return vv
	default:
		return fmt.Sprint(vv)
	}
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
		n, rowWarnings, err := s.sealExisting()
		if err != nil {
			warnings = append(warnings, "sealing the restored secrets failed: "+err.Error())
		} else if n > 0 {
			s.scrub()
		}
		for _, w := range rowWarnings {
			warnings = append(warnings, "the backup holds a secret that does not open and is kept as it is: "+w)
		}
		s.sealWarnings = rowWarnings
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
		rows, err := s.valuesOf(tx, c)
		if err != nil {
			return 0, err
		}
		for _, r := range rows {
			if !seal.IsSealed(r.value) {
				continue
			}
			plain, err := s.box.Open(r.value, r.place)
			if err != nil {
				return 0, fmt.Errorf("%s.%s %s: %w", c.table, c.column, r.key, err)
			}
			if _, err := tx.Exec("UPDATE "+c.table+" SET "+c.column+"=? WHERE "+c.key+"=?", plain, r.key); err != nil {
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
