package engine

import "testing"

// Signatures are bound to what they sign: the same payload signed for one
// purpose never verifies for another.
func TestOIDCSignatureIsPurposeBound(t *testing.T) {
	g := &oidcGate{engine: &engineOIDC{secret: func() []byte { return []byte("0123456789abcdef0123456789abcdef") }}}
	signed := g.sign(oidcStateName, []byte(`{"h":"a.test","x":9999999999,"p":1}`))
	var out oidcSession
	if g.verify(oidcSessionName, signed, &out) {
		t.Fatal("a value signed as login state verified as a session")
	}
	if !g.verify(oidcStateName, signed, &out) {
		t.Fatal("a value did not verify for the purpose it was signed for")
	}
}
