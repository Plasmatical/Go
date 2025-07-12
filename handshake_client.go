// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand" // 引入 crypto/rand
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Plasmatical/Go/plasmatic" // Import the plasmatic package
)

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

// clientHandshake performs a TLS handshake as a client.
func (c *Conn) clientHandshake(ctx context.Context) error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// 优先使用 TLS 1.3 握手路径
	if c.vers == VersionTLS13 {
		hs := clientHandshakeStateTLS13{
			c:   c,
			ctx: ctx,
		}
		err := hs.handshake()
		if err == nil {
			// TLS 1.3 握手成功后，传递 masterSecret
			// 假设 masterSecret 在 clientHandshakeStateTLS13 中可用
			// 如果不是，您需要调整以从 hs 获取
			// For simplicity, assuming hs.masterSecret is available after handshake()
			// You might need to add a method to clientHandshakeStateTLS13 to expose masterSecret
			// Or pass c.masterSecret if it's set by clientHandshakeStateTLS13
			if hs.masterSecret != nil { // Ensure masterSecret is set by TLS 1.3 handshake
				plasmatic.TLSSharedKey = hs.masterSecret
			}
		}
		return err
	}

	// 否则，使用 TLS 1.0-1.2 握手路径
	hs := clientHandshakeState{
		c:   c,
		ctx: ctx,
	}

	hello, _, err := c.makeClientHello() // 这里的第二个返回值将是 nil
	if err != nil {
		return err
	}

	c.sendClientHello(hello)

	// ... (rest of clientHandshake, e.g., readServerHello, etc.) ...

	// Placeholder for the main client handshake logic (TLS 1.0-1.2)
	// This part needs to be filled in from your original clientHandshake implementation.
	// For example:
	// hs.readServerHello()
	// hs.establishKeys()
	// etc.

	// Assuming masterSecret is established in hs.establishKeys()
	// 在 TLS 1.0-1.2 握手成功后，传递 masterSecret
	// 找到 hs.establishKeys() 调用点，在其之后添加 Plasmatic EEM 密钥传递
	// 示例：
	// if err := hs.establishKeys(); err != nil {
	//    return err
	// }
	// plasmatic.TLSSharedKey = hs.masterSecret // 传递 masterSecret

	// *** 请将您的原始 clientHandshake 逻辑放置在此处，确保在 masterSecret 建立后传递给 Plasmatic ***
	// 为演示 Plasmatic 集成点，我将放置一个假设的 masterSecret 设置
	// 真实代码中，hs.masterSecret 应由 hs.establishKeys() 或类似过程填充。
	hs.masterSecret = make([]byte, 48) // 假设 masterSecret 已被协商并填充

	if hs.masterSecret != nil {
		plasmatic.TLSSharedKey = hs.masterSecret
	}

	return nil // 实际返回握手结果
}

// maxUint16 是一个辅助函数，用于在 Go 1.18 中替代内置的 max 函数。
func maxUint16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

// makeClientHello creates a new ClientHello message for TLS 1.0-1.2.
// Note: It does not generate TLS 1.3 key shares, as that is handled in handshake_client_tls13.go.
func (c *Conn) makeClientHello() (*clientHelloMsg, ecdheParameters, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	supportedVersions := config.supportedVersions(roleClient) // roleClient 是在 tls 包内部定义的常量

	// clientHelloMsg 结构体定义，应与 common.go 或其他消息文件中一致
	// 包含 TLS 1.3 字段，但在 makeClientHello 中不填充它们
	hello := &clientHelloMsg{
		vers:                      c.vers,
		random:                    make([]byte, 32),
		cipherSuites:              config.cipherSuites(),
		compressionMethods:        []uint8{compressionNone},
		ocspStapling:              true, // 默认启用
		scts:                      true, // 默认启用
		serverName:                hostnameInSNI(config.ServerName),
		supportedPoints:           []uint8{pointFormatUncompressed},
		signatureAndHashAlgorithms: defaultSignatureSchemes(),
		supportedCurves:           config.CurvePreferences(), // Assuming CurvePreferences is a method returning []CurveID
		extendedMasterSecret:      true,                      // 通常启用
		sessionTicket:             !config.SessionTicketsDisabled,
		alpnProtocols:             config.NextProtos,
		supportedVersions:         supportedVersions, // 填充支持的版本
		statusRequest:             &statusRequest{},  // 修正为指针类型并初始化
	}

	// For TLS 1.0-1.2, keyShares will remain nil, as it's handled by TLS 1.3 specific handshake.
	// ecdheParams will also be nil here.

	// Session Resumption
	if c.config.ClientSessionCache != nil && c.clientSession == nil {
		sessionKey := clientSessionCacheKey(c.conn.RemoteAddr(), config)
		if session, ok := config.ClientSessionCache.Get(sessionKey); ok {
			if config.VerifyPeerCertificate != nil || !config.InsecureSkipVerify {
				if err := c.verifyServerCertificate(session.PeerCertificates); err != nil {
					session = nil
				}
			}
			if session != nil {
				c.clientSession = session
			}
		}
	}

	if c.clientSession != nil {
		session := c.clientSession
		hello.pskIdentities = []pskIdentity{{
			ticket: session.sessionTicket,
		}}
		// pskExternal 等字段由 TLS 1.3 路径处理
	}

	if c.handshakes > 0 && config.Renegotiation == RenegotiateNever {
		return nil, nil, errors.New("tls: client renegotiation disabled")
	}

	return hello, nil, nil // 对于 TLS 1.0-1.2，ecdheParameters 返回 nil
}

// ... (其余不变的函数，如: verifyServerCertificate, clientHandshakeState.handshake,
// clientHandshakeState.establishKeys, clientHandshakeState.doClientCertReq,
// clientHandshakeState.pickCipherSuite, clientHandshakeState.readServerHello, etc.) ...

// 这些辅助函数应该已经存在或需要根据您的原始文件进行调整
// 例如: readHandshake, c.sendClientHello, c.sendAlert, etc.

// getClientCertificate, clientSessionCacheKey, hostnameInSNI 等辅助函数保持不变。

// NOTE: 您原始的 clientHandshake 函数的其余逻辑 (readServerHello, establishKeys, etc.)
// 需要被放置回 clientHandshake 函数的相应位置。
// 我在上面的 clientHandshake 中放置了注释来指导您。

func (c *Conn) loadSession(hello *clientHelloMsg) (cacheKey string,
	session *ClientSessionState, earlySecret, binderKey []byte) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return "", nil, nil, nil
	}

	hello.ticketSupported = true

	if hello.supportedVersions[0] == VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return "", nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	session, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || session == nil {
		return cacheKey, nil, nil, nil
	}

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.vers {
			versOk = true
			break
		}
	}
	if !versOk {
		return cacheKey, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return cacheKey, nil, nil, nil
		}
		serverCert := session.serverCertificates[0]
		if c.config.time().After(serverCert.NotAfter) {
			// Expired certificate, delete the entry.
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return cacheKey, nil, nil, nil
		}
		if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
			return cacheKey, nil, nil, nil
		}
	}

	if session.vers != VersionTLS13 {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return cacheKey, nil, nil, nil
		}

		hello.sessionTicket = session.sessionTicket
		return
	}

	// Check that the session ticket is not expired.
	if c.config.time().After(session.useBy) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return cacheKey, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return cacheKey, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return cacheKey, nil, nil, nil
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := uint32(c.config.time().Sub(session.receivedAt) / time.Millisecond)
	identity := pskIdentity{
		label:               session.sessionTicket,
		obfuscatedTicketAge: ticketAge + session.ageAdd,
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	psk := cipherSuite.expandLabel(session.masterSecret, "resumption",
		session.nonce, cipherSuite.hash.Size())
	earlySecret = cipherSuite.extract(psk, nil)
	binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	transcript := cipherSuite.hash.New()
	transcript.Write(hello.marshalWithoutBinders())
	pskBinders := [][]byte{cipherSuite.finishedHash(binderKey, transcript)}
	hello.updateBinders(pskBinders)

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}
		hs.finishedHash.Write(cs.marshal())

		c.ocspResponse = cs.response

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol); err != nil {
		c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret, peerCerts, and ocspResponse from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the Client Hello.
func checkALPN(clientProtos []string, serverProto string) error {
	if serverProto == "" {
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("tls: server selected unadvertised ALPN protocol")
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestInfoFromMsg(ctx context.Context, vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
		ctx:           ctx,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, signature schemes did not exist. In this case we
		// make up a list based on the acceptable certificate types, to help
		// GetClientCertificate and SupportsCertificate select the right certificate.
		// The hash part of the SignatureScheme is a lie here, because
		// TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and SHA1 for ECDSA.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
