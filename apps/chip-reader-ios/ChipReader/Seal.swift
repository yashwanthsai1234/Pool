// HPKE base mode seal to the console's one-time X-Wing key, matching @legx/core/pq `hpke-xwing-v1`:
// KEM X-Wing (ML-KEM-768 + X25519), KDF HKDF-SHA256, AEAD AES-256-GCM, info "legx/chip-link/v1", aad = sessionId || challenge.
// CryptoKit (iOS 26) has exactly this suite: HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256.
// Source: https://developer.apple.com/documentation/cryptokit/hpke/ciphersuite (verified in the iOS 26.4 SDK swiftinterface)
// Source: https://www.rfc-editor.org/rfc/rfc9180 ; https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ (section 5.6)
import CryptoKit
import Foundation

struct Sealed: Equatable {
    var enc: Data   // 1120 bytes: X-Wing ciphertext
    var ct: Data    // AES-GCM ciphertext || 16-byte tag
}

enum Seal {
    static let info = Data("legx/chip-link/v1".utf8)

    static func aad(_ q: QrContent) -> Data { q.sessionId + q.challenge }

    @available(iOS 26.0, macOS 26.0, *)
    static func seal(_ plaintext: Data, to q: QrContent) throws -> Sealed {
        let pk = try XWingMLKEM768X25519.PublicKey(rawRepresentation: q.publicKey)
        var sender = try HPKE.Sender(recipientKey: pk, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: info)
        let ct = try sender.seal(plaintext, authenticating: aad(q))
        return Sealed(enc: sender.encapsulatedKey, ct: ct)
    }

    /// Used by the tests only (the console opens in Node); proves CryptoKit opens what @hpke/core sealed.
    @available(iOS 26.0, macOS 26.0, *)
    static func open(_ s: Sealed, seed: Data, q: QrContent) throws -> Data {
        let sk = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
        var r = try HPKE.Recipient(privateKey: sk, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: info,
                                   encapsulatedKey: s.enc)
        return try r.open(s.ct, authenticating: aad(q))
    }
}
