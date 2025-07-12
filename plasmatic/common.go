// File: github.com/Plasmatical/Go/plasmatic/common.go
// This file defines constants for the Plasmatic EEM structure and Traffic Pattern Library.

package plasmatic

import "time"

const (
	// EEMFixedLength is the fixed total length of the External Encrypted Mount (EEM) in bytes.
	// This length should be chosen carefully to avoid being a recognizable feature.
	// It must be large enough to contain Nonce, PayloadHeaderFragment, SeedUpdate, and padding.
	EEMFixedLength = 64 // Example: Adjust as needed, must be >= EEMNonceLength + EEMPayloadHeaderFragmentLength + min SeedUpdate size + min padding
	// EEMNonceLength is the length of the Nonce used within the EEM.
	EEMNonceLength = 12 // Using 12 bytes for nonce, common for AEAD ciphers like ChaCha20-Poly1305.
	// EEMPayloadHeaderFragmentLength is the length of the TLS encrypted payload header fragment included in EEM.
	// As per spec, first 2 bytes of encrypted payload.
	EEMPayloadHeaderFragmentLength = 2
	// SeedUpdateMaxLength is the maximum allowed length for the encrypted SeedUpdate data within EEM.
	// EEMFixedLength - EEMNonceLength - EEMPayloadHeaderFragmentLength must be >= SeedUpdateMaxLength.
	SeedUpdateMaxLength = 40 // Example: Adjust based on actual SeedUpdate struct size.

	// MaxPlaintextPayloadSize represents the maximum size of the TLS plaintext payload
	// that Plasmatic expects to receive from the underlying TLS layer.
	// This is typically derived from the TLS record layer's maximum plaintext size.
	// For TLS 1.3, this is 16384 bytes (RFC 8446, Section 5.1).
	MaxPlaintextPayloadSize = 16384
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

// DefaultTrafficPatternLibrary is a concrete implementation of TrafficPatternLibrary.
// In a real scenario, this would be much more complex, potentially involving statistical models.
type DefaultTrafficPatternLibrary struct{}

// NewDefaultTrafficPatternLibrary creates a new instance of DefaultTrafficPatternLibrary.
func NewDefaultTrafficPatternLibrary() *DefaultTrafficPatternLibrary {
	return &DefaultTrafficPatternLibrary{}
}

// GetPayloadSizeForMode provides a basic example of how payload size might be determined
// for various common internet traffic patterns.
// In a real implementation, this would involve complex logic based on the mode and seed
// to generate sizes that closely mimic actual network traffic distributions.
func (tpl *DefaultTrafficPatternLibrary) GetPayloadSizeForMode(modeID uint8, seed int64) int {
	r := newRand(seed) // Use the deterministic pseudo-random number generator
	switch modeID {
	case 0x01: // Web Browsing Mode (smaller packets, bursty)
		// Mimics typical HTTP/HTTPS traffic: varied sizes for small requests, larger for responses.
		// Range: 100-1500 bytes
		return 100 + r.Intn(1401)
	case 0x02: // Video Streaming Mode (larger packets, continuous)
		// Mimics continuous data flow for video, often pushing max payload size.
		// Range: 1000-16000 bytes
		return 1000 + r.Intn(15001)
	case 0x03: // Idle Mode (very small packets, infrequent keep-alives)
		// Mimics minimal background traffic.
		// Range: 10-60 bytes
		return 10 + r.Intn(51)
	case 0x04: // Online Gaming Mode (small, frequent updates, occasional larger state syncs)
		// Mimics interactive game traffic: many small packets for controls, some larger for game state.
		// Bias towards smaller packets, with a chance for medium ones.
		if r.Intn(100) < 70 { // 70% chance for smaller packets
			return 50 + r.Intn(201) // Range: 50-250 bytes
		}
		return 500 + r.Intn(1501) // 30% chance for medium packets, Range: 500-2000 bytes
	case 0x05: // Voice/Video Call Mode (consistent small/medium packets, low latency)
		// Mimics real-time communication with relatively consistent packet sizes.
		// Range: 100-500 bytes
		return 100 + r.Intn(401)
	case 0x06: // Large File Download Mode (max payload size, continuous)
		// Mimics bulk data transfer, aiming for maximum throughput.
		// Uses the defined MaxPlaintextPayloadSize.
		return MaxPlaintextPayloadSize
	case 0x07: // Email Synchronization Mode (variable, often medium-sized bursts, infrequent)
		// Mimics email client syncs: can be small for headers, larger for content.
		// Range: 200-2000 bytes
		return 200 + r.Intn(1801)
	case 0x08: // DNS Over TLS (DoT) / Small Query Mode (very small, consistent)
		// Mimics DNS queries/responses over TLS: typically very small and uniform.
		// Range: 50-150 bytes
		return 50 + r.Intn(101)
	default:
		// Default to a medium size if mode is unknown.
		// Range: 500-1500 bytes
		return 500 + r.Intn(1001)
	}
}

// GetInterPacketDelayForMode provides a basic example of inter-packet delay
// for various common internet traffic patterns.
// This would be used by higher-level Plasmatic logic, not directly by TLS core.
func (tpl *DefaultTrafficPatternLibrary) GetInterPacketDelayForMode(modeID uint8, seed int64) time.Duration {
	r := newRand(seed) // Use the deterministic pseudo-random number generator
	switch modeID {
	case 0x01: // Web Browsing Mode (variable delay, can be bursty)
		// Mimics human interaction: pauses between requests, then bursts of data.
		// Range: 10-110ms
		return time.Duration(r.Intn(100)+10) * time.Millisecond
	case 0x02: // Video Streaming Mode (low, consistent delay)
		// Mimics continuous, low-latency data delivery.
		// Range: 1-5ms
		return time.Duration(r.Intn(5)+1) * time.Millisecond
	case 0x03: // Idle Mode (long delay)
		// Mimics very infrequent keep-alive or background checks.
		// Range: 500-1000ms
		return time.Duration(r.Intn(500)+500) * time.Millisecond
	case 0x04: // Online Gaming Mode (very low, bursty delay)
		// Mimics rapid, interactive input and output.
		// Range: 5-25ms
		return time.Duration(r.Intn(20)+5) * time.Millisecond
	case 0x05: // Voice/Video Call Mode (very low, consistent delay)
		// Mimics real-time, continuous audio/video frames.
		// Range: 10-20ms
		return time.Duration(r.Intn(10)+10) * time.Millisecond
	case 0x06: // Large File Download Mode (minimal delay, continuous)
		// Mimics maximizing throughput, sending packets back-to-back.
		// Range: 1-5ms
		return time.Duration(r.Intn(5)+1) * time.Millisecond
	case 0x07: // Email Synchronization Mode (infrequent, longer pauses)
		// Mimics periodic checks or larger syncs with significant idle periods.
		// Range: 1000-5000ms (1-5 seconds)
		return time.Duration(r.Intn(4000)+1000) * time.Millisecond
	case 0x08: // DNS Over TLS (DoT) / Small Query Mode (variable, quick response, then idle)
		// Mimics quick query-response cycles followed by longer periods of no activity.
		// Range: 50-550ms
		return time.Duration(r.Intn(500)+50) * time.Millisecond
	default:
		// Default to a medium delay if mode is unknown.
		// Range: 50-100ms
		return time.Duration(r.Intn(50)+50) * time.Millisecond
	}
}

// Define a sequence of modes to cycle through.
var modeSequence = []uint8{
	0x01, // Web Browsing
	0x02, // Video Streaming
	0x04, // Online Gaming
	0x05, // Voice/Video Call
	0x06, // Large File Download
	0x07, // Email Synchronization
	0x08, // DNS Over TLS
	0x03, // Idle
}

// modeChangeInterval defines how frequently (in terms of seed increments) a mode change should be considered.
// This is an arbitrary value to simulate a periodic change.
const modeChangeInterval = 10000 // Change mode every 10,000 "units" of seed progression

// GetNextSeedUpdate determines if a seed update is needed based on current state and mode.
// This implementation simulates a deterministic, cyclical mode switching strategy
// based on the progression of the current seed.
// In a real production system, this would integrate with external signals (e.g.,
// detected censorship, user preference, network conditions) and more complex
// heuristics or machine learning models to dynamically select the most
// appropriate traffic pattern.
func (tpl *DefaultTrafficPatternLibrary) GetNextSeedUpdate(currentModeID uint8, currentSeed int64) *SeedUpdate {
	// Check if the current seed progression warrants a mode change.
	// Using modulo ensures a deterministic trigger point.
	if currentSeed%modeChangeInterval == 0 && currentSeed != 0 { // Avoid triggering on initial seed 0
		// Determine the index of the current mode in the sequence.
		currentIndex := -1
		for i, mode := range modeSequence {
			if mode == currentModeID {
				currentIndex = i
				break
			}
		}

		nextModeID := modeSequence[0] // Default to the first mode if current is not found or at end
		if currentIndex != -1 {
			// Calculate the next mode in the sequence.
			nextIndex := (currentIndex + 1) % len(modeSequence)
			nextModeID = modeSequence[nextIndex]
		}

		// Generate a new seed value. For deterministic progression,
		// we can simply increment the current seed or derive it based on a hash.
		// For simplicity and to ensure it's always new, we'll increment.
		newSeedValue := currentSeed + 1 // Ensure new seed is always greater

		// Create the SeedUpdate. Persist is false for automatic cycling.
		return &SeedUpdate{
			ModeID:    nextModeID,
			SeedValue: newSeedValue,
			Persist:   false, // Automatic transitions are not persistent by default
		}
	}

	// No update pending by default if the interval condition is not met.
	return nil
}
