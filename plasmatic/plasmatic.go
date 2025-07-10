// File: github.com/Plasmatical/Go/plasmatic/plasmatic.go
// This file contains the core logic for the Plasmatic protocol.

package plasmatic

import (
	"crypto/cipher"
	"encoding/binary"
	"time"
	"errors"
	"fmt"
	"io"
	"bytes"
	"sync"

	// Import the ChaCha20-Poly1305 implementation
	"golang.org/x/crypto/chacha20poly1305" 
)

// PlasmaticConn represents the state for the Plasmatic protocol on one half-connection (send or receive).
type PlasmaticConn struct {
	eemKey []byte // Shared symmetric key for EEM encryption/decryption

	// Nonce management
	// nextOutgoingNonce is the nonce to be used for the next EEM sent by this side.
	nextOutgoingNonce []byte
	// nextExpectedNonce is the nonce expected in the next EEM received by this side.
	nextExpectedNonce []byte
	nonceMutex        sync.Mutex // Protects nonce updates

	// Seed strategy management
	currentModeID      uint8
	currentSeed        int64
	persistMode        bool // If true, mode is locked until explicitly released
	pendingSeedUpdate  *SeedUpdate // A seed update waiting to be sent in the next EEM
	pendingUpdateMutex sync.Mutex  // Protects pendingSeedUpdate

	// Traffic Pattern Library
	tpl TrafficPatternLibrary
}

// NewPlasmaticConn creates a new PlasmaticConn instance.
// eemKey: The shared symmetric key for EEM operations.
// initialNonce: The initial nonce for this specific direction (derived from DeriveInitialNonce).
// isClient: True if this PlasmaticConn is for the client side, false for server.
//
// This function should be called for both 'in' and 'out' halfConns,
// with appropriate initialNonce derived for each direction.
func NewPlasmaticConn(eemKey []byte, initialNonce []byte, isClient bool) (*PlasmaticConn, error) {
	if len(eemKey) == 0 {
		return nil, errors.New("plasmatic: EEM key cannot be empty")
	}
	if len(initialNonce) != EEMNonceLength {
		return nil, fmt.Errorf("plasmatic: initial nonce length must be %d bytes", EEMNonceLength)
	}

	// For ChaCha20-Poly1305, key length is 32 bytes.
	if len(eemKey) != 32 {
		return nil, errors.New("plasmatic: EEM key must be 32 bytes for ChaCha20-Poly1305")
	}

	pc := &PlasmaticConn{
		eemKey:            eemKey,
		nextOutgoingNonce: make([]byte, EEMNonceLength),
		nextExpectedNonce: make([]byte, EEMNonceLength),
		currentModeID:     0x01, // Default to a common mode, e.g., Web Browse
		currentSeed:       time.Now().UnixNano(), // Initial seed can be time-based or pre-agreed
		tpl:               NewDefaultTrafficPatternLibrary(),
	}
	copy(pc.nextOutgoingNonce, initialNonce)
	copy(pc.nextExpectedNonce, initialNonce) // Initial expected nonce is the same as initial outgoing

	return pc, nil
}

// getCipher creates a ChaCha20-Poly1305 AEAD cipher.
func (pc *PlasmaticConn) getCipher() (cipher.AEAD, error) {
	// ChaCha20-Poly1305 requires a 32-byte key.
	// Corrected: Use chacha20poly1305.New directly for AEAD.
	aead, err := chacha20poly1305.New(pc.eemKey)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// EncodeEEM generates and encrypts the External Encrypted Mount (EEM).
// payloadHeaderFragment: The first 2 bytes of the TLS encrypted payload.
// seedUpdate: Optional, contains instructions for seed change.
// rand: A cryptographically secure random reader (e.g., crypto/rand.Reader).
func (pc *PlasmaticConn) EncodeEEM(payloadHeaderFragment []byte, seedUpdate *SeedUpdate, rand io.Reader) ([]byte, error) {
	if len(payloadHeaderFragment) != EEMPayloadHeaderFragmentLength {
		return nil, fmt.Errorf("plasmatic: payload header fragment must be %d bytes", EEMPayloadHeaderFragmentLength)
	}

	pc.nonceMutex.Lock()
	currentNonce := make([]byte, EEMNonceLength)
	copy(currentNonce, pc.nextOutgoingNonce)
	IncrementNonce(pc.nextOutgoingNonce) // Increment for the next packet
	pc.nonceMutex.Unlock()

	// Build the plaintext EEM payload
	eemPlaintext := make([]byte, EEMFixedLength)
	offset := 0

	// 1. Nonce
	copy(eemPlaintext[offset:offset+EEMNonceLength], currentNonce)
	offset += EEMNonceLength

	// 2. Encrypted Payload Header Fragment
	copy(eemPlaintext[offset:offset+EEMPayloadHeaderFragmentLength], payloadHeaderFragment)
	offset += EEMPayloadHeaderFragmentLength

	// 3. Seed Update (optional)
	if seedUpdate != nil {
		pc.pendingUpdateMutex.Lock()
		pc.pendingSeedUpdate = nil // Clear pending update after including it
		pc.pendingUpdateMutex.Unlock()

		// Marshal SeedUpdate into bytes
		// For simplicity, let's use a fixed-size binary encoding for SeedUpdate
		// Format: ModeID (1 byte) + SeedValue (8 bytes, int64) + Persist (1 byte)
		if offset+10 > EEMFixedLength { // Check if SeedUpdate fits
			return nil, errors.New("plasmatic: SeedUpdate too large for EEM")
		}
		eemPlaintext[offset] = seedUpdate.ModeID
		binary.BigEndian.PutUint64(eemPlaintext[offset+1:], uint64(seedUpdate.SeedValue))
		if seedUpdate.Persist {
			eemPlaintext[offset+9] = 0x01
		} else {
			eemPlaintext[offset+9] = 0x00
		}
		offset += 10 // Size of marshaled SeedUpdate
	}

	// 4. EEM Padding (fill remaining space to EEMFixedLength)
	if offset < EEMFixedLength {
		if _, err := io.ReadFull(rand, eemPlaintext[offset:EEMFixedLength]); err != nil {
			return nil, fmt.Errorf("plasmatic: failed to generate EEM padding: %w", err)
		}
	}

	// Encrypt the EEM plaintext
	aead, err := pc.getCipher()
	if err != nil {
		return nil, err
	}

	// We use the currentNonce as the AEAD nonce for EEM encryption.
	// No additional data for EEM AEAD.
	encryptedEEM := aead.Seal(nil, currentNonce, eemPlaintext, nil)

	if len(encryptedEEM) != EEMFixedLength+aead.Overhead() {
		// This should not happen if EEMFixedLength is correctly calculated for AEAD.
		return nil, errors.New("plasmatic: encrypted EEM length mismatch")
	}

	return encryptedEEM, nil
}

// DecodeEEM decrypts and validates the External Encrypted Mount (EEM).
// encryptedEEM: The received encrypted EEM bytes.
// actualPayloadHeaderFragment: The first 2 bytes of the *decrypted* TLS payload.
func (pc *PlasmaticConn) DecodeEEM(encryptedEEM []byte, actualPayloadHeaderFragment []byte) (*SeedUpdate, error) {
	if len(encryptedEEM) != EEMFixedLength+16 { // Assuming ChaCha20-Poly1305 overhead is 16 bytes
		return nil, errors.New("plasmatic: received EEM has incorrect length")
	}
	if len(actualPayloadHeaderFragment) != EEMPayloadHeaderFragmentLength {
		return nil, fmt.Errorf("plasmatic: actual payload header fragment must be %d bytes", EEMPayloadHeaderFragmentLength)
	}

	pc.nonceMutex.Lock()
	expectedNonce := make([]byte, EEMNonceLength)
	copy(expectedNonce, pc.nextExpectedNonce)
	pc.nonceMutex.Unlock()

	aead, err := pc.getCipher()
	if err != nil {
		return nil, err
	}

	// Decrypt EEM using the expected nonce
	// No additional data for EEM AEAD.
	eemPlaintext, err := aead.Open(nil, expectedNonce, encryptedEEM, nil)
	if err != nil {
		// Decryption failed, likely MAC error or incorrect key/nonce.
		return nil, fmt.Errorf("plasmatic: EEM decryption failed: %w", err)
	}
	if len(eemPlaintext) != EEMFixedLength {
		return nil, errors.New("plasmatic: decrypted EEM plaintext has incorrect length")
	}

	offset := 0
	// 1. Nonce verification
	receivedNonce := eemPlaintext[offset : offset+EEMNonceLength]
	offset += EEMNonceLength

	// Compare received Nonce with expected Nonce
	// This simple comparison assumes strict sequential order.
	// For more robust handling (e.g., allow small windows for reordering),
	// a more complex nonce management system would be needed.
	if !bytes.Equal(receivedNonce, expectedNonce) {
		return nil, errors.New("plasmatic: EEM nonce mismatch or replay detected")
	}

	// Increment expected nonce for the next packet
	pc.nonceMutex.Lock()
	IncrementNonce(pc.nextExpectedNonce)
	pc.nonceMutex.Unlock()

	// 2. Encrypted Payload Header Fragment verification
	receivedPayloadHeaderFragment := eemPlaintext[offset : offset+EEMPayloadHeaderFragmentLength]
	offset += EEMPayloadHeaderFragmentLength

	if !bytes.Equal(receivedPayloadHeaderFragment, actualPayloadHeaderFragment) {
		return nil, errors.New("plasmatic: EEM payload header fragment mismatch")
	}

	// 3. Seed Update (optional)
	var seedUpdate *SeedUpdate
	if offset+10 <= EEMFixedLength && eemPlaintext[offset] != 0x00 { // Assume ModeID 0x00 means no SeedUpdate
		seedUpdate = &SeedUpdate{
			ModeID:    eemPlaintext[offset],
			SeedValue: int64(binary.BigEndian.Uint64(eemPlaintext[offset+1:])),
			Persist:   eemPlaintext[offset+9] == 0x01,
		}
	}

	return seedUpdate, nil
}

// ApplySeedUpdate applies a received seed update to the PlasmaticConn's state.
// isOutgoing: True if this update applies to the outgoing side (e.g., client applying server's instruction).
// False if this update applies to the incoming side (e.g., server applying client's instruction).
func (pc *PlasmaticConn) ApplySeedUpdate(update *SeedUpdate, isOutgoing bool) {
	if update == nil {
		return
	}

	pc.pendingUpdateMutex.Lock()
	defer pc.pendingUpdateMutex.Unlock()

	if pc.persistMode && !update.Persist { // If currently in persist mode, and new update is not persist, it's a release
		pc.persistMode = false
	} else if pc.persistMode { // If currently in persist mode, and new update is also persist, ignore (or re-apply if needed)
		return // Do not change if already persisting and new update also wants to persist
	}

	pc.currentModeID = update.ModeID
	pc.currentSeed = update.SeedValue
	pc.persistMode = update.Persist
	// Log the change for debugging/monitoring
	// fmt.Printf("Plasmatic: Applied new seed update. Mode: %x, Seed: %d, Persist: %t\n", update.ModeID, update.SeedValue, update.Persist)
}

// GetPayloadSizeForMode returns the target TLS plaintext payload size based on the current mode and seed.
// This is called by the TLS layer (maxPayloadSizeForWrite).
func (pc *PlasmaticConn) GetPayloadSizeForMode() int {
	return pc.tpl.GetPayloadSizeForMode(pc.currentModeID, pc.currentSeed)
}

// SetPendingSeedUpdate allows higher-level logic to queue a seed update to be sent in the next EEM.
func (pc *PlasmaticConn) SetPendingSeedUpdate(update *SeedUpdate) {
	pc.pendingUpdateMutex.Lock()
	defer pc.pendingUpdateMutex.Unlock()
	pc.pendingSeedUpdate = update
}

// GetPendingSeedUpdate retrieves the pending seed update and clears it.
func (pc *PlasmaticConn) GetPendingSeedUpdate() *SeedUpdate {
	pc.pendingUpdateMutex.Lock()
	defer pc.pendingUpdateMutex.Unlock()
	update := pc.pendingSeedUpdate
	pc.pendingSeedUpdate = nil // Clear after retrieving
	return update
}

// SetEEMKey allows setting the EEM key after initial handshake if needed (e.g., for re-keying).
func (pc *PlasmaticConn) SetEEMKey(key []byte) error {
	if len(key) != 32 { // ChaCha20-Poly1305 key length
		return errors.New("plasmatic: EEM key must be 32 bytes")
	}
	pc.eemKey = key
	return nil
}

// SetInitialNonce sets the initial nonce for a PlasmaticConn.
// This should be called once after EEMKey is set, typically during handshake.
func (pc *PlasmaticConn) SetInitialNonce(nonce []byte, isOutgoing bool) error {
	if len(nonce) != EEMNonceLength {
		return fmt.Errorf("plasmatic: nonce length must be %d bytes", EEMNonceLength)
	}
	pc.nonceMutex.Lock()
	defer pc.nonceMutex.Unlock()
	if isOutgoing {
		copy(pc.nextOutgoingNonce, nonce)
	} else {
		copy(pc.nextExpectedNonce, nonce)
	}
	return nil
}
