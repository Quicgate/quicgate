package store

import "testing"

func TestAccessListCountryValidation(t *testing.T) {
	// A valid alpha-2 code is accepted and upper-cased.
	a := AccessList{Name: "geo", Rules: []AccessRule{{Action: "allow", Country: "nl"}}}
	if err := a.Validate(nil); err != nil {
		t.Fatalf("valid country rule rejected: %v", err)
	}
	if a.Rules[0].Country != "NL" {
		t.Fatalf("country not upper-cased: %q", a.Rules[0].Country)
	}

	// Anything that is not a 2-letter code is rejected server-side.
	for _, bad := range []string{"NLD", "N1", "netherlands", "N", "N.", "12"} {
		b := AccessList{Name: "geo", Rules: []AccessRule{{Action: "allow", Country: bad}}}
		if err := b.Validate(nil); err == nil {
			t.Errorf("country %q should be rejected", bad)
		}
	}
}

func TestIsCountryCode(t *testing.T) {
	for _, ok := range []string{"NL", "US", "ZW"} {
		if !isCountryCode(ok) {
			t.Errorf("%q should be a valid country code", ok)
		}
	}
	for _, bad := range []string{"nl", "N", "NLD", "N1", "", "US "} {
		if isCountryCode(bad) {
			t.Errorf("%q should not be a valid country code", bad)
		}
	}
}
