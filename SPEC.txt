Internet-Draft                                          D. S. Developer
Intended status: Standards Track                          July 11, 2025
Expires: January 11, 2026

             Plasmatic Protocol: Enhanced Packet Binding and Integrity
                         draft-developer-plasmatic-protocol-03

Abstract

   The Plasmatic Protocol defines a highly dynamic, self-adapting, and
   censorship-resistant communication tunnel. It achieves obfuscation by
   attaching a fixed-length Encrypted External Mount (EEM) outside the
   standard TLS record. The EEM incorporates a monotonically increasing
   Nonce and a fragment of the encrypted TLS payload header, facilitating
   bidirectional seed strategy negotiation. This design allows Plasmatic
   to precisely mimic predefined, legitimate network traffic patterns,
   while ensuring data integrity, replay protection, and strong packet
   binding. This effectively evades Deep Packet Inspection (DPI) and
   traffic analysis.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF). Note that other groups may also distribute
   working documents as Internet-Drafts. The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.

   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time. It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as "work in progress."

   This Internet-Draft will expire on January 11, 2026.

Copyright Notice

   Copyright (c) 2025 IETF Trust and the persons identified as the
   document authors. All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document. Please review these documents
   carefully, as they describe your rights and restrictions with
   respect to this document. Code Components extracted from this
   document must include Revised BSD License text as described in
   Section 4.e of the Trust Legal Provisions and are provided without
   warranty as described in the Revised BSD License.

Table of Contents

   1.  Introduction
     1.1.  Motivation
     1.2.  Goals
   2.  Terminology
   3.  Protocol Overview
   4.  Core Components
     4.1.  Client
     4.2.  Proxy Server
     4.3.  EEM Key
     4.4.  Traffic Pattern Library (TPL)
   5.  Plasmatic Packet Structure
     5.1.  Encrypted External Mount (EEM)
       5.1.1.  EEM Fixed Length
       5.1.2.  EEM Nonce
       5.1.3.  Encrypted Payload Header Fragment
       5.1.4.  Seed Update
       5.1.5.  EEM Padding
   6.  Protocol Flow and Seed Strategy
     6.1.  Initial Handshake and EEM Key/Nonce Synchronization
     6.2.  Tunnel Establishment and Data Transfer
       6.2.1.  Sender Operations
       6.2.2.  Receiver Operations
     6.3.  Bidirectional Seed Strategy Negotiation
   7.  Error Handling and Obfuscation
     7.1.  EEM Validation Failure Conditions
     7.2.  Simulating Normal TLS Error Behavior
   8.  Security Considerations
   9.  IANA Considerations
   10. References
     10.1. Normative References
     10.2. Informative References
   Author's Address

1.  Introduction

1.1.  Motivation

   Current censorship techniques, particularly Deep Packet Inspection
   (DPI) and traffic analysis, pose significant challenges to private
   and unrestricted internet access. Traditional VPNs and proxy
   protocols are often identified and blocked due to their predictable
   traffic patterns or distinctive metadata. There is a critical need
   for a communication protocol that can adapt its observable traffic
   characteristics to mimic legitimate network flows, thereby evading
   detection, while simultaneously ensuring data integrity and
   confidentiality.

1.2.  Goals

   The Plasmatic Protocol aims to achieve the following:
   * **Censorship Resistance**: By mimicking legitimate traffic
      patterns and actively obfuscating its true nature.
   * **Dynamic Adaptability**: Allow for real-time adjustments of
      traffic characteristics based on network conditions or predefined
      strategies.
   * **Data Integrity and Anti-Replay**: Ensure that transmitted data
      is not tampered with and that packets cannot be replayed or
      reordered maliciously.
   * **Strong Packet Binding**: Prevent the independent manipulation
      or replaying of protocol-specific metadata (EEM) by cryptographically
      binding it to its associated TLS encrypted payload.
   * **Low Detectability**: Minimize identifiable signatures through
      fixed-length external data mounts and polymorphic traffic shaping.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174] when they appear in all capitals, as
   shown here.

   **Client**: The user device running the Plasmatic client software.
   **Proxy Server**: A publicly accessible server running the Plasmatic
      server-side software, responsible for communicating with target
      internet services.
   **EEM Key**: A shared symmetric key used for encrypting/decrypting the
      EEM, securely negotiated or pre-configured between the Client and
      Proxy Server.
   **Traffic Pattern Library (TPL)**: A collection of parameters
      defining various legitimate traffic patterns (e.g., web Browse,
      video streaming, online conferencing, gaming) pre-loaded or
      dynamically updated on both Client and Proxy Server. Each pattern
      is defined by one or more seed values and associated behavioral
      rules.
   **EEM**: Encrypted External Mount. A fixed-length, encrypted data
      structure appended to the standard TLS record.
   **Nonce**: Number used once. A value intended to be used only once
      within a specific cryptographic context to prevent replay attacks.

3.  Protocol Overview

   The Plasmatic Protocol operates on top of an established TCP/TLS
   connection. Unlike traditional proxy protocols that encapsulate data
   within the TLS payload, Plasmatic appends a fixed-length Encrypted
   External Mount (EEM) directly after the standard TLS record. This
   EEM carries critical protocol-specific metadata, including an EEM
   Nonce for replay protection, an encrypted fragment of the TLS
   payload header for strong binding, and optional seed update
   information for dynamic traffic shaping. By externally mounting this
   data, Plasmatic can control its observable packet size and timing
   characteristics independently of the actual TLS application data,
   allowing it to mimic legitimate traffic patterns effectively.

4.  Core Components

4.1.  Client

   The Plasmatic Client is software running on the end-user's device. It
   is responsible for initiating connections, encapsulating user data
   into Plasmatic packets, applying traffic shaping based on negotiated
   seed strategies, and handling communication with the Proxy Server.

4.2.  Proxy Server

   The Plasmatic Proxy Server is a publicly deployed server component. It
   acts as an intermediary, receiving Plasmatic packets from clients,
   decapsulating them, forwarding application data to the target internet
   service, and performing reverse operations for inbound traffic. It
   also participates in seed strategy negotiation and traffic shaping.

4.3.  EEM Key

   The EEM Key is a symmetric cryptographic key shared between the
   Client and Proxy Server. It is used exclusively for the authenticated
   encryption and decryption of theEM. This key MUST be established
   securely, for instance, via an initial out-of-band pre-configuration
   or through a secure key exchange mechanism during the initial
   handshake phase of the underlying TLS connection.

4.4.  Traffic Pattern Library (TPL)

   The TPL is a database or configuration set maintained by both the
   Client and Proxy Server. It contains definitions for various
   legitimate network traffic patterns. Each pattern comprises:
   * **Seed Values**: Cryptographic seeds that drive pseudo-random
      number generators for packet sizing, timing, and other
      observable characteristics.
   * **Mode ID**: An identifier for a specific traffic pattern (e.g.,
      "Web Browse", "Video Streaming").
   * **Parameters**: Specific configuration values associated with the
      mode, such as typical packet sizes, inter-packet delays, burst
      characteristics, and allowed deviations.
   The TPL enables Plasmatic to dynamically adjust its traffic
   signature to evade detection.

5.  Plasmatic Packet Structure

   A Plasmatic Protocol packet (PlasmaticPkt) operates on top of the
   underlying TCP/TLS connection. It consists of a standard TLS record
   followed by a unique fixed-length Encrypted External Mount (EEM).

   The conceptual structure is as follows:

      +---------------------------------+
      | TLS Record Header               | (Standard TLS record header:
      +---------------------------------+   Type, Version, Encrypted Length)
      | Encrypted TLS Record Payload    | (User data + TLS protocol
      |   (e.g., HTTP/2 frame)          |   layer padding, encrypted by
      +---------------------------------+   TLS keys)
      | External Encrypted Mount (EEM)  | (Plasmatic Protocol specific,
      |   +---------------------------+ |   **fixed-length**, **encrypted**)
      |   | EEM Nonce (Fixed Length,  | | (Nonce within EEM, encrypted
      |   |   Monotonically Inc.)     | |   under EEM Key)
      |   +---------------------------+ |
      |   | Encrypted Payload Header  | | (First 2 bytes of the encrypted
      |   |   Fragment (2 bytes)      | |   payload, encrypted under EEM Key)
      |   +---------------------------+ |
      |   | Seed Update (Optional)    | | (Encrypted new seed values and
      |   |                           | |   associated instructions)
      |   +---------------------------+ |
      |   | EEM Padding (Fixed length | | (Padding to reach the total
      |   |   to EEM total length)    | |   fixed EEM length)
      |   +---------------------------+ |
      +---------------------------------+

5.1.  Encrypted External Mount (EEM)

   The EEM is a critical component of the Plasmatic Protocol, providing
   obfuscation, integrity, and anti-replay capabilities without
   modifying the underlying TLS record. The entire EEM content (Nonce,
   Encrypted Payload Header Fragment, Seed Update, and EEM Padding)
   MUST be encrypted and authenticated using a robust authenticated
   encryption mode, such as ChaCha20-Poly1305 [RFC8439], with the EEM Key.

5.1.1.  EEM Fixed Length

   The total length of the EEM MUST be determined during protocol
   initialization and remain constant throughout the session. This
   length SHOULD be carefully chosen to avoid becoming an identifiable
   fingerprint and to provide sufficient space for the Nonce, Encrypted
   Payload Header Fragment, Seed Update, and necessary padding.

5.1.2.  EEM Nonce

   Purpose: The EEM Nonce is a fixed-length, monotonically increasing
   value included within each EEM. Its primary purpose is to prevent
   packet replay attacks and detect out-of-order packet injection specific
   to the Plasmatic layer.
   Encryption: The EEM Nonce field itself is part of the EEM's authenticated
   encryption process. It is encrypted and authenticated under the EEM Key.
   Validation: The receiver MUST verify that the decrypted EEM Nonce
   is strictly greater than the last successfully received Nonce for
   that direction of communication. A sliding window or other robust
   replay detection mechanism SHOULD be employed.

5.1.3.  Encrypted Payload Header Fragment

   Purpose: This field is a crucial mechanism to prevent the EEM from
   being independently cut and replayed onto a different TLS encrypted
   record, or from being crafted without knowledge of the actual TLS
   payload. It creates a strong cryptographic binding between the EEM
   and its co-located TLS encrypted payload.
   Content: The Plasmatic Protocol mandates that the EEM MUST contain
   the first 2 bytes of the *encrypted* TLS Record Payload (i.e., the
   payload after TLS encryption, but before Plasmatic processing) of the
   current Plasmatic packet. These 2 bytes represent a critical fragment
   of the encrypted application data.
   Encryption: These 2 bytes of the encrypted payload fragment are
   themselves encrypted under the EEM Key before being placed into the
   EEM. This provides an additional layer of obfuscation and protection
   for this binding mechanism.
   Validation: Upon receiving a Plasmatic packet, after decrypting the
   EEM with the EEM Key, the receiver MUST extract these 2 bytes. The
   receiver then compares these extracted bytes with the actual first 2
   bytes of the received Encrypted TLS Record Payload. If there is a
   mismatch, it MUST be considered a binding error, indicating potential
   tampering or a replay attempt.

5.1.4.  Seed Update (Optional)

   The Seed Update field, if present, carries encrypted new seed values
   and associated control instructions. This field enables the dynamic
   and bidirectional negotiation of traffic shaping strategies, allowing
   both the Client and Proxy Server to update each other's TPL parameters.
   The specific format and content of the Seed Update are outside the
   scope of this document but MUST be encrypted under the EEM Key.

5.1.5.  EEM Padding

   EEM Padding consists of arbitrary data used to fill the EEM to its
   pre-determined fixed length. This padding MUST be random or pseudo-
   randomly generated to avoid creating identifiable patterns. It is
   part of the overall EEM encryption process.

6.  Protocol Flow and Seed Strategy

6.1.  Initial Handshake and EEM Key/Nonce Synchronization

   1.  The Client and Proxy Server establish an underlying TCP
       connection.
   2.  A standard TLS handshake is performed over this TCP connection.
       This handshake establishes a secure channel for subsequent
       Plasmatic communication.
   3.  The EEM Key is securely negotiated or pre-configured between
       the Client and Proxy Server. This key MUST be independent of the
       TLS session keys.
   4.  The initial EEM Nonce values for both directions of communication
       are synchronized or agreed upon. This can be done via secure
       exchange over the established TLS channel or through pre-shared
       knowledge.

6.2.  Tunnel Establishment and Data Transfer

   Once the initial setup is complete, all subsequent Plasmatic data
   packets MUST include a fixed-length EEM appended to the TLS record.

6.2.1.  Sender Operations

   For each outgoing PlasmaticPkt:
   1.  The sender (Client or Proxy Server) constructs a standard TLS
       record, which includes the Encrypted TLS Record Payload (user
       data plus TLS padding, encrypted by the TLS session keys).
   2.  The sender extracts the **first 2 bytes** of this *encrypted*
       TLS Record Payload.
   3.  A new, monotonically increasing EEM Nonce is generated.
   4.  The EEM Nonce, the extracted 2-byte Encrypted Payload Header
       Fragment, optional Seed Update information, and necessary EEM
       Padding are concatenated.
   5.  This concatenated EEM content is then encrypted and authenticated
       using the EEM Key and a robust AEAD cipher (e.g., ChaCha20-Poly1305).
   6.  The resulting encrypted EEM is appended immediately after the
       TLS record.
   7.  The combined TLS record + EEM is then sent over the TCP connection.

6.2.2.  Receiver Operations

   For each incoming PlasmaticPkt:
   1.  The receiver (Client or Proxy Server) receives the combined TLS
       record and the fixed-length EEM.
   2.  The EEM is extracted from its fixed offset after the TLS record.
   3.  The receiver attempts to decrypt the EEM using the shared EEM Key.
       This step includes verifying the integrity of the EEM using the
       AEAD tag.
   4.  **EEM Nonce Validation**: Upon successful EEM decryption, the
       receiver MUST extract the EEM Nonce. It then checks if this Nonce
       is valid (e.g., strictly increasing and within an acceptable
       replay window). If invalid, the packet MUST be discarded, and
       error handling (Section 7) MUST be initiated.
   5.  **Encrypted Payload Header Fragment Validation**: The receiver
       extracts the 2-byte Encrypted Payload Header Fragment from the
       decrypted EEM. It then compares these 2 bytes with the actual
       first 2 bytes of the received Encrypted TLS Record Payload (which
       precedes the EEM). If they do not match, it indicates a binding
       error, and the packet MUST be discarded, initiating error handling.
   6.  Only if the EEM decryption, Nonce validation, and Encrypted Payload
       Header Fragment validation are all successful, the receiver proceeds
       to process the Plasmatic layer's user data and any Seed Update.

6.3.  Bidirectional Seed Strategy Negotiation

   Seed values and associated control instructions (e.g., mode ID,
   parameter adjustments, solidification commands) are carried encrypted
   within the optional Seed Update field of the EEM.
   Both the Client and Proxy Server can independently include Seed Update
   information in their respective outgoing EEMs, thereby dynamically
   controlling the traffic shaping behavior of the other party and their
   own. The specific negotiation and "solidification" mechanisms for
   seed values and traffic patterns remain consistent with previous
   iterations of the protocol.

7.  Error Handling and Obfuscation

   A critical aspect of Plasmatic's censorship resistance is its error
   handling. When an EEM anomaly is detected, the protocol MUST NOT
   expose its presence. Instead, it MUST simulate normal TLS error
   behavior to an external observer.

7.1.  EEM Validation Failure Conditions

   An EEM validation failure occurs under any of the following conditions:
   * **Missing EEM**: The received packet does not contain the
      expected fixed-length EEM at the specified offset.
   * **EEM Decryption Failure**: The EEM Key's AEAD MAC (Message
      Authentication Code) check fails during EEM decryption,
      indicating tampering or an incorrect key.
   * **Incorrect Nonce**: The decrypted EEM Nonce does not conform to
      expectations (e.g., duplicated, out-of-order beyond an
      acceptable window, or invalid format).
   * **Encrypted Payload Header Fragment Mismatch**: The 2-byte
      fragment extracted from the decrypted EEM does not match the
      actual first 2 bytes of the Encrypted TLS Record Payload that
      precedes the EEM.
   * **Malformed EEM**: The internal structure of the decrypted EEM
      does not conform to the Plasmatic Protocol's defined format
      (e.g., incorrect field lengths or parsing errors).

7.2.  Simulating Normal TLS Error Behavior

   When a receiver detects any of the EEM validation failures listed
   above, it MUST:
   1.  Immediately stop processing the Plasmatic layer and any user
       data associated with that packet.
   2.  **Simulate an underlying TLS layer error**:
       * **Send a TLS Alert message**: This is the preferred and most
          protocol-compliant way to signal an error. The specific Alert
          message SHOULD be chosen to mimic common TLS integrity or
          decryption failures:
          * `bad_record_mac (20)` [RFC8446]: This is the most suitable
             general-purpose integrity error. It SHOULD be used when EEM
             decryption fails (MAC check), Nonce validation fails, or the
             Encrypted Payload Header Fragment does not match. This alert
             code plausibly indicates that "the received record appears to
             have been tampered with or is incomplete."
          * `decrypt_error (21)` [RFC8446]: May be considered if the
             failure is specifically attributed to a decryption issue
             within the EEM.
          * `decode_error (50)` [RFC8446]: May be considered if the EEM
             is missing or its internal structure, once decrypted, is
             completely unparsable, indicating "I cannot understand the
             format of the record you sent."
       * **Terminate the Connection**: After sending the appropriate TLS
          Alert message, the underlying TCP connection SHOULD be
          immediately closed. This is a common and expected behavior for
          standard TLS error handling.

   By following these error handling procedures, no information
   directly indicating an "EEM error" or "Plasmatic Protocol error"
   will be returned. External observers (censors) will only perceive a
   seemingly normal TLS error, such as a `bad_record_mac` alert,
   followed by a connection termination. This makes it appear as a
   standard network glitch, a detected Man-in-the-Middle (MITM) attack,
   or a TLS configuration issue, rather than exposing the presence of
   the Plasmatic proxy protocol.

8.  Security Considerations

   * **EEM Key Management**: The security of the Plasmatic Protocol
      heavily relies on the secure establishment and management of the
      EEM Key. Compromise of this key directly leads to compromise of
      the EEM's confidentiality and integrity, potentially allowing
      detection or manipulation of Plasmatic traffic. Key agreement
      SHOULD leverage strong, ephemeral key exchange mechanisms.
   * **Nonce Security**: The EEM Nonce MUST be properly managed to
      prevent replay attacks. Implementations MUST ensure strict
      monotonicity and employ a robust replay detection window. Reuse of
      a Nonce with the same EEM Key is a catastrophic failure that
      compromises the AEAD scheme.
   * **Payload Header Fragment Binding**: The 2-byte Encrypted Payload
      Header Fragment provides a strong binding. The choice of 2 bytes
      is a trade-off between EEM overhead and binding strength. While it
      does not protect against all forms of advanced traffic analysis
      (e.g., length-based), it significantly raises the bar for
      independent EEM manipulation.
   * **Fixed EEM Length**: The fixed length of the EEM is a design
      choice for obfuscation. However, if an attacker can precisely
      identify this fixed length (e.g., through side-channel attacks or
      traffic analysis on initial connection patterns), it could become
      a fingerprint. Implementations SHOULD consider mechanisms to vary
      this length within a session, if feasible without introducing
      identifiable patterns.
   * **Traffic Pattern Library Obfuscation**: The effectiveness of the
      TPL relies on the legitimacy and diversity of its patterns. Poorly
      designed or limited patterns could still allow for statistical
      detection. The Seed Update mechanism helps in dynamically adapting
      patterns, but the TPL itself should be regularly updated and
      diverse.
   * **Underlying TLS Security**: Plasmatic relies on a secure TLS
      connection. All standard TLS security best practices (e.g., using
      TLS 1.3, strong cipher suites, proper certificate validation) MUST
      be adhered to. Plasmatic does not aim to replace or bypass TLS
      security.
   * **Covert Channel Potential**: The Seed Update mechanism, while
      intended for protocol control, inherently has the potential for
      covert channel communication. Implementations SHOULD be designed to
      minimize this risk and ensure that only authorized and expected
      control messages are exchanged.

9.  IANA Considerations

   This memo includes no IANA considerations.

10. References

10.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Ought to and Should in RFCs",
              BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
              <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8439]  Josefsson, S., "ChaCha20 and Poly1305 for IETF Protocols",
              RFC 8439, DOI 10.17487/RFC8439, June 2018,
              <https://www.rfc-editor.org/info/rfc8439>.

   [RFC8446]  Rescorla, E., "The Transport Layer Security (TLS) Protocol
              Version 1.3", RFC 8446, DOI 10.17487/RFC8446, August 2018,
              <https://www.rfc-editor.org/info/rfc8446>.

10.2.  Informative References

   None.

Author's Address

   D. S. Developer
   Email: your.email@example.com (Replace with your actual email)
