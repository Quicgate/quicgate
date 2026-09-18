package wg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// NewPrivateKey makes a server key, clamped as WireGuard expects.
func NewPrivateKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// NewPresharedKey makes the symmetric key every peer gets on top of its
// keypair.
func NewPresharedKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// PublicKey derives the public key that belongs to a private key.
func PublicKey(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil || len(raw) != 32 {
		return "", errors.New("a WireGuard key is 32 bytes in base64")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
