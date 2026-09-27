package engine

import "testing"

// Signatures are bound to what they sign: the same payload signed for one
// purpose never verifies for another.
func TestOIDCSignatureIsPurposeBound(t *testing.T) {
	g := &oidcGate{engine: &engineOIDC{secret: func() []byte { return []byte("0123456789abcdef0123456789abcdef") }}}
	signed, err := g.sign(oidcStateName, []byte(`{"h":"a.test","x":9999999999,"p":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var out oidcSession
	if g.verify(oidcSessionName, signed, &out) {
		t.Fatal("a value signed as login state verified as a session")
	}
	if !g.verify(oidcStateName, signed, &out) {
		t.Fatal("a value did not verify for the purpose it was signed for")
	}
}

// Without a signing key nothing is signed and nothing verifies: an HMAC over
// an empty key would be one anybody can compute.
func TestOIDCNoSigningKeySignsNothing(t *testing.T) {
	withKey := &oidcGate{engine: &engineOIDC{secret: func() []byte { return []byte("0123456789abcdef0123456789abcdef") }}}
	signed, err := withKey.sign(oidcSessionName, []byte(`{"e":"a@example.com","h":"a.test","x":9999999999,"p":1}`))
	if err != nil {
		t.Fatal(err)
	}
	noKey := &oidcGate{engine: &engineOIDC{secret: func() []byte { return nil }}}
	if _, err := noKey.sign(oidcSessionName, []byte(`{}`)); err == nil {
		t.Fatal("a value was signed without a key")
	}
	var out oidcSession
	if noKey.verify(oidcSessionName, signed, &out) {
		t.Fatal("a value verified without a key")
	}
}
