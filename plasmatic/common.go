// File: github.com/Plasmatical/Go/plasmatic/common.go
// This file defines constants for the Plasmatic EEM structure.

package plasmatic

const (
	// EEMFixedLength is the fixed total length of the External Encrypted Mount (EEM) in bytes.
	// This length should be chosen carefully to avoid being a recognizable feature.
	// It must be large enough to contain Nonce, PayloadHeaderFragment, SeedUpdate, and padding.
	EEMFixedLength = 64 // Example: Adjust as needed, must be >= EEMNonceLength + EEMPayloadHeaderFragmentLength + min SeedUpdate size + min padding
	// EEMNonceLength is the length of the Nonce used within the EEM.
	EEMNonceLength = 12 // Using 12 bytes for nonce, common for AEAD ciphers like ChaCha20-Poly1305.
	// EEMPayloadHeaderFragmentLength is the length of the TLS encrypted payload header fragment included in EEM.
	EEMPayloadHeaderFragmentLength = 2 // As per spec, first 2 bytes of encrypted payload.
	// SeedUpdateMaxLength is the maximum allowed length for the encrypted SeedUpdate data within EEM.
	// EEMFixedLength - EEMNonceLength - EEMPayloadHeaderFragmentLength must be >= SeedUpdateMaxLength.
	SeedUpdateMaxLength = 40 // Example: Adjust based on actual SeedUpdate struct size.
)

// SeedUpdate represents the parameters for dynamically adjusting the traffic mode.
// This struct will be encrypted and carried within the EEM.
type SeedUpdate struct {
	// ModeID identifies the specific traffic pattern from the Traffic Pattern Library.
	ModeID uint8
	// SeedValue is the new seed to be used for the selected mode.
	SeedValue int64
	// Persist indicates if this mode should be locked until explicitly changed.
	Persist bool
	// Direction indicates which side's behavior this update applies to (e.g., client's or server's).
	// This is useful for asymmetric control, though the current spec implies mutual control.
	// For now, it's implicit in who sends/receives, but could be explicit if needed.
	// For simplicity, we'll assume it applies to the receiver's behavior.
}

// TrafficPatternLibrary defines an interface for managing different traffic patterns.
type TrafficPatternLibrary interface {
	// GetPayloadSizeForMode returns the target TLS plaintext payload size based on the current mode and seed.
	// This size will be used by the TLS layer's maxPayloadSizeForWrite.
	GetPayloadSizeForMode(modeID uint8, seed int64) int
	// GetInterPacketDelayForMode returns a suggested delay based on the current mode and seed.
	// (Not directly used by TLS core, but useful for higher-level Plasmatic logic).
	GetInterPacketDelayForMode(modeID uint8, seed int64) time.Duration
	// GetNextSeedUpdate determines if a seed update is needed based on current state and mode.
	// (Higher-level logic will call this to decide what to put in EEM).
	GetNextSeedUpdate(currentModeID uint8, currentSeed int64) *SeedUpdate
}

// DefaultTrafficPatternLibrary is a placeholder for a concrete implementation of TrafficPatternLibrary.
// In a real scenario, this would be much more complex, potentially involving statistical models.
type DefaultTrafficPatternLibrary struct{}

// NewDefaultTrafficPatternLibrary creates a new instance of DefaultTrafficPatternLibrary.
func NewDefaultTrafficPatternLibrary() *DefaultTrafficPatternLibrary {
	return &DefaultTrafficPatternLibrary{}
}

// GetPayloadSizeForMode provides a basic example of how payload size might be determined.
// In a real implementation, this would involve complex logic based on the mode and seed.
func (tpl *DefaultTrafficPatternLibrary) GetPayloadSizeForMode(modeID uint8, seed int64) int {
	// This is a simplified example. A real implementation would use the seed
	// to derive a pseudo-random size within the constraints of the mode.
	// For instance, seed could influence a PRNG to pick a size from a distribution.
	switch modeID {
	case 0x01: // Web Browsing Mode (smaller packets, bursty)
		// Example: use seed to pick a size between 100 and 1000 bytes
		// For deterministic pseudo-randomness based on seed:
		r := newRand(seed)
		return 100 + r.Intn(901) // Size between 100 and 1000
	case 0x02: // Video Streaming Mode (larger packets, continuous)
		// Example: use seed to pick a size between 1000 and 16000 bytes
		r := newRand(seed)
		return 1000 + r.Intn(15001) // Size between 1000 and 16000
	case 0x03: // Idle Mode (very small packets, infrequent)
		r := newRand(seed)
		return 10 + r.Intn(51) // Size between 10 and 60
	default:
		// Default to a medium size if mode is unknown.
		r := newRand(seed)
		return 500 + r.Intn(1001) // Size between 500 and 1500
	}
}

// GetInterPacketDelayForMode provides a basic example of inter-packet delay.
// This would be used by higher-level Plasmatic logic, not directly by TLS core.
func (tpl *DefaultTrafficPatternLibrary) GetInterPacketDelayForMode(modeID uint8, seed int64) time.Duration {
	r := newRand(seed)
	switch modeID {
	case 0x01: // Web Browsing Mode (variable delay)
		return time.Duration(r.Intn(100)+10) * time.Millisecond // 10-110ms
	case 0x02: // Video Streaming Mode (low, consistent delay)
		return time.Duration(r.Intn(5)+1) * time.Millisecond // 1-5ms
	case 0x03: // Idle Mode (long delay)
		return time.Duration(r.Intn(500)+500) * time.Millisecond // 500-1000ms
	default:
		return time.Duration(r.Intn(50)+50) * time.Millisecond // 50-100ms
	}
}

// GetNextSeedUpdate is a placeholder. In a real system, this would be driven by
// external signals (e.g., detected censorship, user preference) and internal heuristics.
func (tpl *DefaultTrafficPatternLibrary) GetNextSeedUpdate(currentModeID uint8, currentSeed int64) *SeedUpdate {
	// For demonstration, let's assume a simple state machine or external trigger.
	// In a real scenario, this would be much more complex.
	return nil // No update pending by default
}


