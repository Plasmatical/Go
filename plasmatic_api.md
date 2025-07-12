# Plasmatic Protocol: Complete Function Reference

This document provides the most comprehensive and detailed reference for all user-defined functions in `plasmatic/plasmatic.go` (and related types in `plasmatic/common.go`). Each function is explained with its signature, expected parameters, return values, side effects, and usage context.

---

## PlasmaticConn: Core State Structure

```go
type PlasmaticConn struct {
    eemKey []byte

    // Nonce management
    nextOutgoingNonce []byte
    nextExpectedNonce []byte
    nonceMutex sync.Mutex

    // Seed strategy management
    currentModeID uint8
    currentSeed int64
    persistMode bool
    pendingSeedUpdate *SeedUpdate
    pendingUpdateMutex sync.Mutex

    // Traffic Pattern Library
    tpl TrafficPatternLibrary
}
```

- Each PlasmaticConn manages the state for one direction of a connection (send or receive).

---

## Function List and Details

### 1. **NewPlasmaticConn**

```go
func NewPlasmaticConn(eemKey []byte, initialNonce []byte, isClient bool) (*PlasmaticConn, error)
```

- **Purpose:** Create and initialize a new `PlasmaticConn` instance for either client or server direction.
- **Parameters:**
  - `eemKey []byte`: Shared symmetric key for EEM encryption/decryption (must be 32 bytes for ChaCha20-Poly1305).
  - `initialNonce []byte`: Initial nonce for this connection direction (length must match EEMNonceLength, e.g., 12 bytes).
  - `isClient bool`: Indicates if this is for the client side (`true`) or server side (`false`).
- **Returns:** Pointer to new `PlasmaticConn` and error if validation fails.
- **Side effects:** Sets up initial mode, seed, and traffic pattern library.
- **Usage:** Call after handshake, once keys and nonces are established.

---

### 2. **EncodeEEM**

```go
func (pc *PlasmaticConn) EncodeEEM(
  payloadHeaderFragment []byte,
  seedUpdate *SeedUpdate,
  rand io.Reader
) ([]byte, error)
```

- **Purpose:** Generate and encrypt the External Encrypted Mount (EEM) to append after a TLS record.
- **Parameters:**
  - `payloadHeaderFragment []byte`: First 2 bytes of encrypted TLS payload for binding.
  - `seedUpdate *SeedUpdate`: Optional. If present, will be included for a mid-session traffic pattern change.
  - `rand io.Reader`: Cryptographically secure random source for padding.
- **Returns:** The encrypted EEM bytes and error if any.
- **Details:** 
  - Handles nonce management, seed update marshaling, and AEAD encryption.
  - If `seedUpdate` is provided, clears any pending updates after encoding.
- **Usage:** Called for every outgoing TLS record that needs an EEM attached.

---

### 3. **DecodeEEM**

```go
func (pc *PlasmaticConn) DecodeEEM(
  encryptedEEM []byte,
  actualPayloadHeaderFragment []byte
) (*SeedUpdate, error)
```

- **Purpose:** Decrypt and validate a received EEM, verifying integrity and extracting optional seed update.
- **Parameters:**
  - `encryptedEEM []byte`: The received encrypted EEM.
  - `actualPayloadHeaderFragment []byte`: The first 2 bytes of the decrypted TLS payload (for binding check).
- **Returns:** Extracted `*SeedUpdate` (if present), or nil. Error on decryption/validation failure.
- **Details:** 
  - Validates nonce for anti-replay, checks payload fragment for integrity.
  - Increments expected nonce after correct decryption.
- **Usage:** Call for each received TLS record with EEM.

---

### 4. **ApplySeedUpdate**

```go
func (pc *PlasmaticConn) ApplySeedUpdate(update *SeedUpdate, isOutgoing bool)
```

- **Purpose:** Apply a received seed update to change traffic pattern parameters.
- **Parameters:**
  - `update *SeedUpdate`: New mode/seed/persist info.
  - `isOutgoing bool`: True if for outgoing direction, false otherwise.
- **Details:** Handles persist logic and updates mode/seed.
- **Usage:** After extracting a seed update from a received EEM, call this to update connection state.

---

### 5. **SetPendingSeedUpdate**

```go
func (pc *PlasmaticConn) SetPendingSeedUpdate(update *SeedUpdate)
```

- **Purpose:** Queue a seed update to be included in the next EEM sent.
- **Parameters:** `update *SeedUpdate` to send.
- **Details:** Thread-safe; can be called from higher layers.
- **Usage:** To trigger a mid-session traffic pattern change.

---

### 6. **GetPendingSeedUpdate**

```go
func (pc *PlasmaticConn) GetPendingSeedUpdate() *SeedUpdate
```

- **Purpose:** Retrieve and clear the pending seed update (for internal use during EEM encoding).
- **Returns:** The current pending update or nil.
- **Details:** Thread-safe.
- **Usage:** Called by EncodeEEM.

---

### 7. **SetEEMKey**

```go
func (pc *PlasmaticConn) SetEEMKey(key []byte) error
```

- **Purpose:** Set or update the EEM key (for rekeying).
- **Parameters:** `key []byte` (must be 32 bytes).
- **Returns:** Error if invalid.
- **Usage:** For rekeying after initial handshake.

---

### 8. **SetInitialNonce**

```go
func (pc *PlasmaticConn) SetInitialNonce(nonce []byte, isOutgoing bool) error
```

- **Purpose:** Set the initial nonce after key setup, for outgoing or incoming direction.
- **Parameters:**
  - `nonce []byte`: Initial nonce value.
  - `isOutgoing bool`: True for nextOutgoingNonce, false for nextExpectedNonce.
- **Returns:** Error if length is invalid.
- **Usage:** Used during handshake or after rekey.

---

### 9. **GetPayloadSizeForMode**

```go
func (pc *PlasmaticConn) GetPayloadSizeForMode() int
```

- **Purpose:** Get the recommended TLS application payload size, based on current mode/seed.
- **Returns:** Payload size in bytes.
- **Usage:** Used by TLS layer for padding/fragmentation.

---

### 10. **getCipher** (internal)

```go
func (pc *PlasmaticConn) getCipher() (cipher.AEAD, error)
```

- **Purpose:** Create a ChaCha20-Poly1305 AEAD cipher with the current EEM key.
- **Returns:** AEAD cipher instance.
- **Usage:** Internal, called by EncodeEEM/DecodeEEM.

---

## Traffic Pattern Library Interface

### `TrafficPatternLibrary`

```go
type TrafficPatternLibrary interface {
    GetPayloadSizeForMode(modeID uint8, seed int64) int
    GetInterPacketDelayForMode(modeID uint8, seed int64) time.Duration
    GetNextSeedUpdate(currentModeID uint8, currentSeed int64) *SeedUpdate
}
```

- Provides strategies for dynamic traffic shaping.
- **Default Implementation:** `DefaultTrafficPatternLibrary` (see `common.go`).

---

## SeedUpdate Structure

```go
type SeedUpdate struct {
    ModeID uint8
    SeedValue int64
    Persist bool
    // Direction (optional for future use)
}
```

- Encapsulates dynamic traffic shaping changes.
- Can be sent in EEM as part of live negotiation.

---

## Example Usage

```go
// Initialization (after handshake)
conn, err := NewPlasmaticConn(eemKey, initialNonce, true)
if err != nil { panic(err) }

// Set a seed update
conn.SetPendingSeedUpdate(&SeedUpdate{ModeID: 2, SeedValue: 12345, Persist: false})

// Encode EEM for outgoing record
eem, err := conn.EncodeEEM(payloadFragment, conn.GetPendingSeedUpdate(), cryptoRand)
if err != nil { ... }

// Decode EEM on receive
seedUpd, err := conn.DecodeEEM(receivedEEM, payloadFragment)
if seedUpd != nil {
    conn.ApplySeedUpdate(seedUpd, false)
}
```

---

**For further protocol-level meaning, see `SPEC.md`. For default traffic patterns and more, see `common.go`.**
