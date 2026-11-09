package authx

import "golang.org/x/crypto/bcrypt"

// The tests hash at bcrypt's minimum cost. At the production cost every sign-in and signup costs
// seconds under the race detector, which took the package past go test's ten-minute timeout.
func init() {
	bcryptCost = bcrypt.MinCost
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer-not-a-real-password"), bcryptCost)
}
