// Package seal encrypts the secrets quicgate keeps in its database, so that a
// leaked database file or backup archive does not hand over client secrets,
// private keys and tokens. It protects against a leaked database, not against
// someone who can read the whole data directory when the key lives there too.
//
// A sealed value is text: "qgs1.<key id>.<base64url(nonce || ciphertext)>",
// XChaCha20-Poly1305 with a random nonce per value. The associated data names
// where the value belongs (table, column, row, purpose), so a ciphertext that
// is moved to another row or column does not open.
package seal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	prefix  = "qgs1."
	keySize = chacha20poly1305.KeySize

	// KeyFileName is the key file quicgate keeps in its data directory when no
	// key is supplied from outside.
	KeyFileName = "secret.key"
	envKey      = "QG_SECRET_KEY"
	envKeyFile  = "QG_SECRET_KEY_FILE"
)

// ErrLocked is returned when a sealed value cannot be opened because the key
// that sealed it is not available.
var ErrLocked = errors.New("sealed with a key that is not available")

// Box seals and opens values. It holds one primary key, which seals, and any
// number of older keys, which only open (for rotation and restored backups).
// A nil *Box is valid and locked: it opens nothing and seals nothing.
type Box struct {
	primary string
	keys    map[string][]byte
	source  string // where the keys came from, for the startup message
}

// IsSealed reports whether v is a sealed value.
func IsSealed(v string) bool { return strings.HasPrefix(v, prefix) }

// KeyID names a key without revealing it.
func KeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("quicgate seal key id\x00"), key...))
	return hex.EncodeToString(sum[:4])
}

// New returns a Box that seals with keys[0] and opens with all of them.
func New(keys ...[]byte) (*Box, error) {
	if len(keys) == 0 {
		return nil, errors.New("seal: no key")
	}
	b := &Box{keys: map[string][]byte{}}
	for i, k := range keys {
		if len(k) != keySize {
			return nil, fmt.Errorf("seal: key %d is %d bytes, want %d", i+1, len(k), keySize)
		}
		id := KeyID(k)
		b.keys[id] = append([]byte(nil), k...)
		if i == 0 {
			b.primary = id
		}
	}
	return b, nil
}

// HasKey reports whether the box holds the key with this id.
func (b *Box) HasKey(id string) bool {
	if b == nil {
		return false
	}
	_, ok := b.keys[id]
	return ok
}

// Usable reports whether the box can seal.
func (b *Box) Usable() bool { return b != nil && b.primary != "" }

// PrimaryID is the id of the key that seals.
func (b *Box) PrimaryID() string {
	if b == nil {
		return ""
	}
	return b.primary
}

// Source says where the keys came from.
func (b *Box) Source() string {
	if b == nil {
		return ""
	}
	return b.source
}

// Seal encrypts plaintext for the place aad names. The empty string stays
// empty: it means "no secret", and is not worth hiding.
func (b *Box) Seal(plaintext, aad string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if !b.Usable() {
		return "", ErrLocked
	}
	aead, err := chacha20poly1305.NewX(b.keys[b.primary])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return prefix + b.primary + "." + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a sealed value for the place aad names. A value that is not
// sealed is returned as it is: that is how values written before sealing
// existed are read until the migration has sealed them.
func (b *Box) Open(value, aad string) (string, error) {
	if !IsSealed(value) {
		return value, nil
	}
	id, body, ok := strings.Cut(value[len(prefix):], ".")
	if !ok {
		return "", errors.New("seal: malformed value")
	}
	if b == nil {
		return "", ErrLocked
	}
	key, ok := b.keys[id]
	if !ok {
		return "", ErrLocked
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", errors.New("seal: malformed value")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("seal: malformed value")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(aad))
	if err != nil {
		return "", errors.New("seal: value does not open here (wrong place, or damaged)")
	}
	return string(plain), nil
}

// NeedsReseal reports whether value should be sealed again: it is plaintext,
// or sealed with a key that is no longer the primary one.
func (b *Box) NeedsReseal(value string) bool {
	if value == "" || !b.Usable() {
		return false
	}
	if !IsSealed(value) {
		return true
	}
	id, _, _ := strings.Cut(value[len(prefix):], ".")
	return id != b.primary
}

// parseKeys reads keys from text: one base64 key per line, the first is the
// primary. Blank lines and lines starting with # are skipped.
func parseKeys(text string) ([][]byte, error) {
	var keys [][]byte
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			k, err = base64.RawStdEncoding.DecodeString(line)
		}
		if err != nil || len(k) != keySize {
			return nil, fmt.Errorf("a key must be %d bytes in base64", keySize)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no key found")
	}
	return keys, nil
}

// Load finds the keys for the database in dataDir. Order: the file named by
// QG_SECRET_KEY_FILE, the key in QG_SECRET_KEY, the file secret.key in the
// data directory. With none of them it creates secret.key, unless mayCreate
// is false: the caller passes false when the database already holds sealed
// values, because a fresh key could open none of them and would only hide
// that the real key is missing.
func Load(dataDir string, mayCreate bool) (*Box, error) {
	if path := os.Getenv(envKeyFile); path != "" {
		text, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envKeyFile, err)
		}
		return fromText(string(text), envKeyFile+" ("+path+")")
	}
	if v := os.Getenv(envKey); v != "" {
		return fromText(v, envKey)
	}
	path := filepath.Join(dataDir, KeyFileName)
	text, err := os.ReadFile(path)
	if err == nil {
		return fromText(string(text), path)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if !mayCreate {
		return nil, fmt.Errorf("%w: %s is missing and neither %s nor %s is set", ErrLocked, path, envKeyFile, envKey)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	content := "# quicgate secret key. It opens the secrets in quicgate.db. Keep it out of backups you share.\n" +
		base64.StdEncoding.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	b, err := New(key)
	if err != nil {
		return nil, err
	}
	b.source = path + " (created now)"
	return b, nil
}

func fromText(text, source string) (*Box, error) {
	keys, err := parseKeys(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	b, err := New(keys...)
	if err != nil {
		return nil, err
	}
	b.source = source
	return b, nil
}
