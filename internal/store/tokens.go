package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

// What an API token may do. A token is made for one job, and a dashboard that
// only shows whether things are up has no business holding the key to the
// whole configuration.
const (
	// TokenFull does everything the management API offers.
	TokenFull = "full"
	// TokenMonitor reads status: hosts and whether their backends answer,
	// certificates, traffic, bans, metrics. No settings, no logs, no backups,
	// no host configuration, and it changes nothing.
	TokenMonitor = "monitor"
	// TokenSwitch is TokenMonitor plus switching a proxy host on or off.
	TokenSwitch = "switch"
)

// APIToken is a long-lived bearer token for the management API. Only the
// SHA-256 hash is stored; the raw value is shown once at creation.
type APIToken struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Access    string `json:"access"` // full | monitor | switch
	CreatedAt string `json:"createdAt"`
	Token     string `json:"token,omitempty"` // populated only on create
}

func (s *Store) migrateTokens() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  hash TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL
)`)
	if err != nil {
		return err
	}
	// Tokens made before access levels existed could do everything, and still can.
	if _, err := s.db.Exec("ALTER TABLE api_tokens ADD COLUMN access TEXT NOT NULL DEFAULT 'full'"); err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// tokenPrefix is how a raw token starts, per access level, so a token says
// what it is wherever it turns up.
func tokenPrefix(access string) string {
	switch access {
	case TokenMonitor:
		return "qgm_"
	case TokenSwitch:
		return "qgs_"
	}
	return "qg_"
}

// tokenAccessOf reads the access level a raw token claims from its prefix.
func tokenAccessOf(raw string) string {
	switch {
	case strings.HasPrefix(raw, "qgm_"):
		return TokenMonitor
	case strings.HasPrefix(raw, "qgs_"):
		return TokenSwitch
	}
	return TokenFull
}

// hashToken is what the database keeps of a token. A full token hashes as it
// always did. A limited token mixes its level into the hash: a quicgate from
// before access levels looks tokens up by the plain hash and reads every hit
// as full access, so after a downgrade a limited token matches nothing there
// instead of being promoted.
func hashToken(raw, access string) string {
	in := raw
	if access != TokenFull {
		in = "quicgate api token\x00" + access + "\x00" + raw
	}
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}

func (s *Store) ListAPITokens() ([]APIToken, error) {
	rows, err := s.db.Query("SELECT id, name, access, created_at FROM api_tokens ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Access, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateAPIToken makes a token with full access.
func (s *Store) CreateAPIToken(name string) (*APIToken, error) {
	return s.CreateAPITokenFor(name, TokenFull)
}

// CreateAPITokenFor makes a token of one access level.
func (s *Store) CreateAPITokenFor(name, access string) (*APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("token name is required")
	}
	switch access {
	case TokenFull, TokenMonitor, TokenSwitch:
	default:
		return nil, errors.New(`what the token may do must be "full", "monitor" or "switch"`)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	raw := tokenPrefix(access) + hex.EncodeToString(buf)
	res, err := s.db.Exec("INSERT INTO api_tokens (name, hash, access, created_at) VALUES (?,?,?,?)", name, hashToken(raw, access), access, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &APIToken{ID: id, Name: name, Access: access, CreatedAt: now(), Token: raw}, nil
}

// TokenAccess reports what a raw bearer token may do, and whether it is a
// token at all. The level a token claims by its prefix has to be the level it
// was stored with; anything else is no token.
func (s *Store) TokenAccess(raw string) (string, bool) {
	claimed := tokenAccessOf(raw)
	var stored string
	err := s.db.QueryRow("SELECT access FROM api_tokens WHERE hash=?", hashToken(raw, claimed)).Scan(&stored)
	if err != nil || stored != claimed {
		return "", false
	}
	return stored, true
}

func (s *Store) DeleteAPIToken(id int64) error {
	res, err := s.db.Exec("DELETE FROM api_tokens WHERE id=?", id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
