package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/store"
)

// An unknown user costs a real bcrypt comparison, like a wrong password for a
// known user, so the response time does not tell a probe which usernames
// exist. The stand-in hash used before was 41 bytes long, which bcrypt refused
// in microseconds against tens of milliseconds for a real comparison.
func TestUnknownBasicAuthUserCostsAComparison(t *testing.T) {
	const cost = bcrypt.MinCost + 2 // fast enough for a test, slow enough to time
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), cost)
	if err != nil {
		t.Fatal(err)
	}
	c := compileAccess(store.AccessList{Name: "t", Satisfy: "all",
		Users: []store.AccessUser{{Username: "known", Hash: string(hash)}}}, nil, nil, nil)

	// The decoy is a valid bcrypt hash at the cost of the stored hashes...
	if got, err := bcrypt.Cost(c.decoy); err != nil || got != cost || len(c.decoy) != 60 {
		t.Fatalf("decoy %q: cost %d, %v; want a 60-byte bcrypt hash at cost %d", c.decoy, got, err, cost)
	}
	// ...that bcrypt compares in full rather than refusing on sight.
	if err := bcrypt.CompareHashAndPassword(c.decoy, []byte("guess")); err != bcrypt.ErrMismatchedHashAndPassword {
		t.Fatalf("comparing against the decoy: %v, want a plain mismatch", err)
	}

	refuse := func(user string) time.Duration {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", basic(user, "wrong"))
		best := time.Hour
		for i := 0; i < 5; i++ {
			start := time.Now()
			if c.authOK(r) {
				t.Fatalf("%q with a wrong password was accepted", user)
			}
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	known, unknown := refuse("known"), refuse("nobody")
	if unknown < known/4 {
		t.Fatalf("an unknown user is refused in %v, a known one in %v: the difference gives the usernames away", unknown, known)
	}
}

// One decoy per cost, made once: a reload with many lists does not pay for a
// hash per list, and lists with hashes of different costs get matching decoys.
func TestDecoyHashFollowsStoredCost(t *testing.T) {
	low, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	high, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost+1)
	if got := bcryptCostOf(map[string]string{"a": string(low), "b": string(high)}); got != bcrypt.MinCost+1 {
		t.Fatalf("cost of a mixed list = %d, want the highest, %d", got, bcrypt.MinCost+1)
	}
	if got := bcryptCostOf(map[string]string{"a": "$2a$10$invalidinvalidinvalidinvalidinvali"}); got != bcrypt.DefaultCost {
		t.Fatalf("cost of a list whose hash does not parse = %d, want the store's default %d", got, bcrypt.DefaultCost)
	}
	if got := bcryptCostOf(map[string]string{"a": "$2a$31$" + string(low[7:])}); got != maxDecoyCost {
		t.Fatalf("cost of a list claiming cost 31 = %d, want the cap %d", got, maxDecoyCost)
	}
	if a, b := dummyBcryptHash(bcrypt.MinCost), dummyBcryptHash(bcrypt.MinCost); string(a) != string(b) {
		t.Fatal("two decoys for one cost: the hash is not reused")
	}
}
