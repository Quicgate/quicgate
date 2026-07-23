package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

// APIToken is a long-lived bearer token for the management API. Only the
// SHA-256 hash is stored; the raw value is shown once at creation.
type APIToken struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
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
	return err
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) ListAPITokens() ([]APIToken, error) {
	rows, err := s.db.Query("SELECT id, name, created_at FROM api_tokens ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) CreateAPIToken(name string) (*APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("token name is required")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	raw := "qg_" + hex.EncodeToString(buf)
	res, err := s.db.Exec("INSERT INTO api_tokens (name, hash, created_at) VALUES (?,?,?)", name, hashToken(raw), now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &APIToken{ID: id, Name: name, CreatedAt: now(), Token: raw}, nil
}

// ValidAPIToken reports whether a raw bearer token matches a stored hash.
func (s *Store) ValidAPIToken(raw string) bool {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE hash=?", hashToken(raw)).Scan(&n)
	return err == nil && n > 0
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
