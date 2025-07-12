# Plasmatical TLS Library (with Plasmatic Protocol Integration)

This project is a highly customized fork of the standard Go TLS library, extended with deep integration of the **Plasmatic Protocol**. It is designed for censorship resistance, advanced traffic obfuscation, and anti-replay protection, making it ideal for secure tunneling and stealth networking applications.

## Overview

The Plasmatic Protocol operates on top of a standard TLS 1.3 connection, but with a key enhancement: after every TLS record, a fixed-length **Encrypted External Mount (EEM)** is appended. This EEM encapsulates protocol-specific metadata, including a cryptographic nonce, a fragment of the encrypted payload, and optional traffic shaping controls (seed updates). This approach enables the connection to dynamically mimic legitimate traffic patterns, making it highly resistant to deep packet inspection (DPI) and traffic analysis.

Key features:

- **Censorship Resistance:** Mimics real-world network flows to evade detection.
- **Strong Data Integrity & Anti-Replay:** Each packet bound cryptographically to its payload and protected by nonces.
- **Dynamic Traffic Shaping:** Real-time adjustment of observable characteristics (size, timing) via a Traffic Pattern Library (TPL).
- **Replay and Tamper Protection:** All protocol metadata is cryptographically bound to the TLS record.

## How It Works

1. **TLS Handshake**: The client and server perform a standard TLS 1.3 handshake, deriving the shared master secret and traffic secrets.
2. **EEM Key Derivation**: A symmetric EEM key (independent of the TLS session keys) is established between client and server. This can be either negotiated or pre-shared.
3. **Plasmatic Connection Initialization**: Both client and server initialize their `PlasmaticConn` using the EEM key and a direction-specific initial nonce, derived from the TLS handshake.
4. **Data Transfer**:
    - For every outgoing TLS record, the sender extracts the first 2 bytes of the encrypted payload and constructs an EEM. The EEM includes:
        - A unique, increasing nonce
        - The encrypted payload fragment
        - Optional seed/traffic pattern updates
    - The EEM is encrypted using ChaCha20-Poly1305 with the EEM key, then appended to the TLS record.
    - The receiver decrypts and validates the EEM, checking the nonce and verifying the cryptographic binding to the payload.
5. **Traffic Pattern Library (TPL)**: Both sides maintain a set of legitimate traffic patterns (mode IDs, seeds, parameters) to dynamically adjust packet size, timing, and burst behavior.

For complete protocol details, see [`SPEC.md`](./SPEC.md).

## Usage

### 1. Build and Integration

This repository replaces the standard Go TLS library. To use Plasmatic TLS in your project:

- Clone this repository and build your Go application against it. (Make sure your import paths point to `github.com/Plasmatical/Go`.)
- Integrate the Plasmatic protocol logic on both client and server sides.

### 2. Core API Example

The core logic is in `plasmatic/plasmatic.go`.

```go
import "github.com/Plasmatical/Go/plasmatic"

// Derive EEM Key and Initial Nonce (after TLS handshake)
eemKey := ...           // 32 bytes (from handshake or pre-shared)
initialNonce := ...     // from DeriveInitialNonce()
isClient := true        // or false, depending on side

conn, err := plasmatic.NewPlasmaticConn(eemKey, initialNonce, isClient)
if err != nil {
    panic(err)
}

// To encode an EEM for outgoing packet:
payloadFragment := ... // first 2 bytes of TLS encrypted payload
eem, err := conn.EncodeEEM(payloadFragment, nil, cryptoRandReader)
if err != nil {
    // handle error
}

// To decode/validate EEM for incoming packet:
fragment, err := conn.DecodeEEM(receivedEEM, expectedPayloadFragment)
if err != nil {
    // handle tamper/replay error
}
```

**Note:** You must patch the TLS handshake logic to invoke Plasmatic initialization at the appropriate points. See the comments in `handshake_client_tls13.go` and `handshake_server_tls13.go` for integration requirements:
- Add fields to your TLS connection struct (e.g., `PlasmaticClientConn`, `PlasmaticServerConn`)
- Call `NewPlasmaticConn` during the handshake after traffic secrets are established.

### 3. EEM Key Management

- The EEM key **must** be a securely generated 32-byte value, unique for each session and direction.
- Initial nonces **must** be synchronized between client and server, using a secure exchange.

## Security Considerations

- **EEM Key Security:** Compromise of the EEM key fully compromises Plasmatic's confidentiality and integrity.
- **TLS Best Practices:** Always use strong TLS versions and ciphers. Plasmatic does not replace the underlying TLS security.
- **Pattern Diversity:** Regularly update and diversify TPL patterns to avoid detection by statistical analysis.

For more detailed threat models and operational recommendations, see the "Security Considerations" section in [`SPEC.md`](./SPEC.md).

## References

- [SPEC.md: Plasmatic Protocol Specification](./SPEC.md)
- See source code documentation in `plasmatic/plasmatic.go` for API details.

---

**Disclaimer:** This project is for advanced users and research purposes. Integration with production systems requires deep understanding of both TLS internals and active network adversaries.
