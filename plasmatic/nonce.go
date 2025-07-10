
// File: [github.com/Plasmatical/Go/plasmatic/nonce.go](https://github.com/Plasmatical/Go/plasmatic/nonce.go)
// This file contains logic for deriving an initial Nonce for Plasmatic EEM.

package plasmatic

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveInitialNonce deterministically derives an initial Nonce from the EEM Key.
// This ensures both client and server can independently calculate the same starting Nonce
// without explicit transmission, based on their shared EEM Key and a directional context.
//
// eemKey: The shared symmetric key used for EEM encryption.
// isClient: True if this is the client side, false if server side.
// Returns a byte slice of EEMNonceLength.
func DeriveInitialNonce(eemKey []byte, isClient bool) []byte {
	// Use HMAC-SHA256 as a KDF to derive the initial nonce.
	// The context string ensures different nonces for client-to-server and server-to-client directions.
	var context string
	if isClient {
		context = "plasmatic-client-nonce" // Client's outgoing nonce derivation context
	} else {
		context = "plasmatic-server-nonce" // Server's outgoing nonce derivation context
	}

	h := hmac.New(sha256.New, eemKey)
	h.Write([]byte(context))
	derivedKey := h.Sum(nil)

	// Take the first EEMNonceLength bytes of the derived key.
	if len(derivedKey) < EEMNonceLength {
		// This should not happen with SHA256 (32 bytes output) if EEMNonceLength is 12.
		// If it does, pad with zeros or panic based on desired behavior.
		panic("plasmatic: derived nonce too short")
	}

	return derivedKey[:EEMNonceLength]
}

// IncrementNonce increments the given nonce byte slice.
// It treats the nonce as a big-endian unsigned integer.
// Panics if nonce length is not EEMNonceLength.
func IncrementNonce(nonce []byte) {
	if len(nonce) != EEMNonceLength {
		panic("plasmatic: nonce length mismatch during increment")
	}

	// Increment as a big-endian integer
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 { // No overflow, done
			return
		}
	}
	// If we reach here, it means the nonce has wrapped around (all bytes became 0).
	// This is highly unlikely for a 12-byte nonce in practice.
	// In a real system, this might trigger a re-keying or connection close.
	panic("plasmatic: EEM nonce wraparound")
}

