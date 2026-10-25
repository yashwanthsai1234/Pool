// Checks the Swift transfer encoding, QR parsing and HPKE X-Wing seal against vector.json made by @legx/chip-link in Node
// (tools/gen-vector.ts), and writes a Swift-sealed bundle for Node to open (tools/gen-vector.ts open <file>).
import CryptoKit
import XCTest
@testable import ChipReader

final class TransferTests: XCTestCase {
    struct Vec: Decodable {
        let qr, sessionId, challenge, secretKey, wireOnlyDg1Sod, plaintext, enc, ct: String
        let fields: [String: String]
    }
    func vec() throws -> Vec {
        let url = Bundle(for: TransferTests.self).url(forResource: "vector", withExtension: "json")!
        return try JSONDecoder().decode(Vec.self, from: Data(contentsOf: url))
    }
    func full(_ v: Vec) -> ChipData {
        ChipData(dg1: [UInt8](Data(hex: v.fields["dg1"]!)!), sod: [UInt8](Data(hex: v.fields["sod"]!)!),
                 dg14: [UInt8](Data(hex: v.fields["dg14"]!)!), dg15: [UInt8](Data(hex: v.fields["dg15"]!)!),
                 aaSignature: [UInt8](Data(hex: v.fields["aa"]!)!))
    }

    func testWireMatchesNode() throws {
        let v = try vec()
        XCTAssertEqual(try ChipTransfer.encode(full(v)).hex, v.plaintext)
        XCTAssertEqual(try ChipTransfer.encode(ChipData(dg1: [9, 9, 9], sod: [8, 8])).hex, v.wireOnlyDg1Sod)
    }
    func testQrParses() throws {
        let v = try vec()
        let q = try XCTUnwrap(QrContent.parse(v.qr))
        XCTAssertEqual(q.sessionId.hex, v.sessionId); XCTAssertEqual(q.challenge.hex, v.challenge)
        XCTAssertEqual(q.publicKey.count, 1216)
        XCTAssertNil(QrContent.parse(v.qr + ":x")); XCTAssertNil(QrContent.parse("legxchip2:" + v.qr.dropFirst(10)))
    }
    func testCryptoKitOpensNodeSealed() throws {
        guard #available(iOS 26.0, *) else { throw XCTSkip("needs iOS 26") }
        let v = try vec(); let q = try XCTUnwrap(QrContent.parse(v.qr))
        let pt = try Seal.open(Sealed(enc: Data(hex: v.enc)!, ct: Data(hex: v.ct)!), seed: Data(hex: v.secretKey)!, q: q)
        XCTAssertEqual(pt.hex, v.plaintext)
        // wrong aad (another session) must fail
        var other = q; other.sessionId = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try Seal.open(Sealed(enc: Data(hex: v.enc)!, ct: Data(hex: v.ct)!), seed: Data(hex: v.secretKey)!, q: other))
    }
    func testSwiftSealOpensInNode() throws {
        guard #available(iOS 26.0, *) else { throw XCTSkip("needs iOS 26") }
        let v = try vec(); let q = try XCTUnwrap(QrContent.parse(v.qr))
        let pt = try ChipTransfer.encode(full(v))
        let s = try Seal.seal(pt, to: q)
        XCTAssertEqual(s.enc.count, 1120)
        XCTAssertEqual(try Seal.open(s, seed: Data(hex: v.secretKey)!, q: q), pt)
        let out: [String: String] = ["qr": v.qr, "sessionId": v.sessionId, "challenge": v.challenge, "secretKey": v.secretKey,
                                      "enc": s.enc.hex, "ct": s.ct.hex, "plaintext": pt.hex]
        try JSONSerialization.data(withJSONObject: out).write(to: URL(fileURLWithPath: "/tmp/chipreader-ios-sealed.json"))
    }
    func testMrzCheckDigit() {
        // ICAO 9303 Part 3 specimen: L898902C3 -> 6, 740812 -> 2, 120415 -> 9
        XCTAssertEqual(Mrz.key(documentNumber: "L898902C3", birth: "740812", expiry: "120415"), "L898902C36740812" + "2" + "120415" + "9")
    }

    func testRelayRequestShape() throws {
        let sid = Data((0..<16).map { UInt8($0) })
        let r = try Relay.request(base: "http://192.168.1.5:3000/", sessionId: sid, sealed: Sealed(enc: Data([0, 1, 2]), ct: Data([3, 4, 5])))
        XCTAssertEqual(r.url?.absoluteString, "http://192.168.1.5:3000/chip-link/000102030405060708090a0b0c0d0e0f")
        XCTAssertEqual(r.httpMethod, "POST")
        let b = try JSONSerialization.jsonObject(with: r.httpBody!) as! [String: String]
        XCTAssertEqual(b, ["sessionId": sid.hex, "enc": "AAEC", "ct": "AwQF"])
        XCTAssertThrowsError(try Relay.request(base: "not a url", sessionId: sid, sealed: Sealed(enc: Data(), ct: Data())))
    }
}
