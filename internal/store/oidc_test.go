package store

import (
	"strings"
	"testing"
)

// The SSO session lifetime has a ceiling. Sessions are stateless: a cookie is
// valid until it expires, so a lifetime of years is a credential that cannot
// be taken back.
func TestOIDCProviderSessionHoursAreCapped(t *testing.T) {
	provider := func(hours int) *OIDCProvider {
		return &OIDCProvider{Name: "idp", Issuer: "https://idp.example.com/realms/x", ClientID: "quicgate", SessionHours: hours}
	}
	if err := provider(MaxSessionHours + 1).Validate(); err == nil || !strings.Contains(err.Error(), "720") {
		t.Fatalf("a session lifetime over the cap validated: %v", err)
	}
	if err := provider(24 * 365).Validate(); err == nil {
		t.Fatal("a session lifetime of a year validated")
	}
	if err := provider(MaxSessionHours).Validate(); err != nil {
		t.Fatalf("the cap itself must be allowed: %v", err)
	}
	p := provider(0)
	if err := p.Validate(); err != nil || p.SessionHours != 12 {
		t.Fatalf("the default lifetime: %d, %v, want 12 hours", p.SessionHours, err)
	}
	if err := provider(-1).Validate(); err == nil {
		t.Fatal("a negative lifetime validated")
	}

	// The cap holds at the store's door too, not only in Validate.
	noKeyEnv(t)
	st, err := Open(t.TempDir() + "/quicgate.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateOIDCProvider(provider(MaxSessionHours + 1)); err == nil {
		t.Fatal("the store accepted a provider with a session lifetime over the cap")
	}
	ok := provider(48)
	if err := st.CreateOIDCProvider(ok); err != nil {
		t.Fatal(err)
	}
	ok.SessionHours = MaxSessionHours * 2
	if err := st.UpdateOIDCProvider(ok); err == nil {
		t.Fatal("the store accepted an update to a session lifetime over the cap")
	}
}
