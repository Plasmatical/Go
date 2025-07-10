// newRand creates a new pseudo-random number generator seeded with the given value.
// This is for deterministic behavior based on the seed.
// For cryptographically secure randomness, use crypto/rand.Reader.

package plasmatic

import (
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"time"
)

type randSource struct {
	seed int64
}

func newRand(seed int64) *randSource {
	return &randSource{seed: seed}
}

func (r *randSource) Intn(n int) int {
	r.seed = (r.seed*1664525 + 1013904223) % 4294967296 // Simple LCG
	return int(r.seed % int64(n))
}
