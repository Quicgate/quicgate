package seal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, keySize) }

// A sealed value opens only in the place it was sealed for.
func TestSealedValueIsBoundToItsPlace(t *testing.T) {
	box, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("client-secret-123", "oidc_providers/client_secret/7")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) || strings.Contains(sealed, "client-secret-123") {
		t.Fatalf("sealed value %q is not sealed", sealed)
	}
	if got, err := box.Open(sealed, "oidc_providers/client_secret/7"); err != nil || got != "client-secret-123" {
		t.Fatalf("open in place = %q, %v", got, err)
	}
	for _, elsewhere := range []string{"oidc_providers/client_secret/8", "custom_certs/key_pem/7", ""} {
		if got, err := box.Open(sealed, elsewhere); err == nil {
			t.Errorf("opened for %q as %q: a moved ciphertext must not open", elsewhere, got)
		}
	}
	again, _ := box.Seal("client-secret-123", "oidc_providers/client_secret/7")
	if again == sealed {
		t.Fatal("sealing the same value twice gave the same text: the nonce is not random")
	}
}

// The empty string is no secret, plaintext passes through Open, and damage is
// an error rather than garbage.
func TestEmptyPlaintextAndDamage(t *testing.T) {
	box, _ := New(key(1))
	if s, err := box.Seal("", "x"); err != nil || s != "" {
		t.Fatalf("Seal(\"\") = %q, %v", s, err)
	}
	if got, err := box.Open("written-before-sealing", "x"); err != nil || got != "written-before-sealing" {
		t.Fatalf("plaintext through Open = %q, %v", got, err)
	}
	sealed, _ := box.Seal("secret", "x")
	damaged := sealed[:len(sealed)-2] + "AA"
	if _, err := box.Open(damaged, "x"); err == nil {
		t.Fatal("a damaged value opened")
	}
	for _, bad := range []string{prefix, prefix + "abcd", prefix + box.PrimaryID() + ".!!!", prefix + box.PrimaryID() + ".AAAA"} {
		if _, err := box.Open(bad, "x"); err == nil {
			t.Errorf("malformed value %q opened", bad)
		}
	}
}

// Without the key a sealed value reports ErrLocked, and a nil box is locked.
func TestMissingKeyIsLocked(t *testing.T) {
	one, _ := New(key(1))
	two, _ := New(key(2))
	sealed, _ := one.Seal("secret", "x")
	if _, err := two.Open(sealed, "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("another key: %v, want ErrLocked", err)
	}
	var none *Box
	if _, err := none.Open(sealed, "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("nil box: %v, want ErrLocked", err)
	}
	if _, err := none.Seal("secret", "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("nil box sealed: %v, want ErrLocked", err)
	}
	if got, err := none.Open("plain", "x"); err != nil || got != "plain" {
		t.Fatalf("nil box and plaintext = %q, %v", got, err)
	}
}

// Rotation: a box with a new primary key still opens what the old key sealed,
// and says that it should be sealed again.
func TestRotationKeepsOldValuesReadable(t *testing.T) {
	old, _ := New(key(1))
	sealed, _ := old.Seal("secret", "x")
	rotated, err := New(key(2), key(1))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.Open(sealed, "x"); err != nil || got != "secret" {
		t.Fatalf("after rotation = %q, %v", got, err)
	}
	if !rotated.NeedsReseal(sealed) || !rotated.NeedsReseal("plaintext") {
		t.Fatal("a value under the old key, or in plaintext, should need resealing")
	}
	fresh, _ := rotated.Seal("secret", "x")
	if rotated.NeedsReseal(fresh) || rotated.NeedsReseal("") {
		t.Fatal("a value under the primary key, or the empty value, needs no resealing")
	}
	if _, err := old.Open(fresh, "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("the old key alone opened a value sealed by the new one: %v", err)
	}
}

// Load creates a key file once, reads it back, prefers the environment, and
// refuses to invent a key when the database already holds sealed values.
func TestLoad(t *testing.T) {
	t.Setenv(envKey, "")
	t.Setenv(envKeyFile, "")
	dir := t.TempDir()

	if _, err := Load(dir, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("no key and mayCreate=false: %v, want ErrLocked", err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); !os.IsNotExist(err) {
		t.Fatal("a key file was created although sealed values exist")
	}

	first, err := Load(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrimaryID() != second.PrimaryID() {
		t.Fatal("the key file did not give the same key on the second load")
	}
	sealed, _ := first.Seal("secret", "x")
	if got, err := second.Open(sealed, "x"); err != nil || got != "secret" {
		t.Fatalf("second load cannot open: %q, %v", got, err)
	}

	t.Setenv(envKey, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=") // 32 x 'A'
	fromEnv, err := Load(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if fromEnv.PrimaryID() == first.PrimaryID() || fromEnv.Source() != envKey {
		t.Fatalf("the environment key was not preferred (source %q)", fromEnv.Source())
	}
	t.Setenv(envKey, "too-short")
	if _, err := Load(dir, true); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}
