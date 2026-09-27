package admin

import (
	"log"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// A TOTP code is valid for its own 30-second step and, to allow for clock
// drift, the step on either side. Within that window a code seen on the wire
// (a phishing page, a shoulder, a log) opens the account again, unless the
// verifier remembers the last step it accepted and refuses that step and any
// earlier one (RFC 6238, section 5.2). Every place a code is checked for an
// account goes through verifyTOTP, which does exactly that, with the step
// recorded in the account's row so the check survives a restart and two
// logins presenting the same code at once cannot both pass.

// totpPeriod is the step length totp.Generate sets up every secret with.
const totpPeriod = 30

// totpNow is the clock codes are checked against; tests move it.
var totpNow = time.Now

// totpStep returns the time step the code is valid for, within one step of
// now, and whether it is valid at all. Digits and algorithm are the defaults
// of totp.Generate, which made every secret here.
func totpStep(code, secret string, now time.Time) (int64, bool) {
	t := now.Unix() / totpPeriod
	for _, step := range []int64{t, t + 1, t - 1} {
		ok, err := hotp.ValidateCustom(code, uint64(step), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return step, true
		}
	}
	return 0, false
}

// verifyTOTP checks a code against the account's secret and records the step
// it belongs to. It refuses a code of a step the account has already signed
// in with (last), so the same code never opens the account twice. The secret
// is a parameter because 2FA enable confirms a secret that is not stored yet.
func (s *Server) verifyTOTP(userID, last int64, secret, code string) bool {
	step, ok := totpStep(code, secret, totpNow())
	if !ok || step <= last {
		return false
	}
	used, err := s.store.UseTOTPCounter(userID, step)
	if err != nil {
		log.Printf("admin: recording the used two-factor code: %v", err)
		return false
	}
	return used
}
