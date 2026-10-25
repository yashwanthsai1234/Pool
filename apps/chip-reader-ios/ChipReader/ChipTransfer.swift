// The chip-link transfer format and QR parsing. Must produce the same bytes as packages/chip-link/src/wire.ts.
// Layout: "LGXC" || version(1) || fields, each tag(1) || length(4, big endian) || value; tags ascend, DG1 and SOD required.
// Source: packages/chip-link/src/wire.ts, channel.ts; DESIGN.md 6.15
import Foundation

struct ChipData: Equatable {
    var dg1: [UInt8]
    var sod: [UInt8]
    var dg14: [UInt8]? = nil
    var dg15: [UInt8]? = nil
    /// The chip's INTERNAL AUTHENTICATE answer to the 8-byte challenge.
    var aaSignature: [UInt8]? = nil
}

enum ChipTransfer {
    static let magic: [UInt8] = [0x4c, 0x47, 0x58, 0x43]
    static let version: UInt8 = 1
    static let maxField = 1 << 20

    enum EncodeError: Error { case tooLarge }

    static func encode(_ d: ChipData) throws -> Data {
        var out = magic + [version]
        let fields: [(UInt8, [UInt8]?)] = [(1, d.dg1), (2, d.sod), (3, d.dg14), (4, d.dg15), (5, d.aaSignature)]
        for (tag, value) in fields {
            guard let v = value else { continue }
            guard v.count <= maxField else { throw EncodeError.tooLarge }
            let n = UInt32(v.count)
            out += [tag, UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)] + v
        }
        return Data(out)
    }
}

/// `legxchip1:<session hex>:<challenge hex>:<X-Wing public key base64url, no padding>`
struct QrContent: Equatable {
    var sessionId: Data   // 16 bytes
    var challenge: Data   // 8 bytes: RND.IFD for Active Authentication (first 8 bytes of presenceMsg, OD-23)
    var publicKey: Data   // 1216 bytes

    static func parse(_ s: String) -> QrContent? {
        let p = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard p.count == 4, p[0] == "legxchip1",
              p[1].count == 32, p[2].count == 16,
              let sid = Data(hex: p[1]), let ch = Data(hex: p[2]),
              let pk = Data(base64URLNoPad: p[3]) else { return nil }
        return QrContent(sessionId: sid, challenge: ch, publicKey: pk)
    }
}

extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0, hex.allSatisfy({ $0.isHexDigit && ($0.isNumber || $0.isLowercase) }) else { return nil }
        var d = Data(); var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            d.append(UInt8(hex[i..<j], radix: 16)!); i = j
        }
        self = d
    }
    init?(base64URLNoPad s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard !s.contains("="), s.count % 4 != 1 else { return nil }
        b += String(repeating: "=", count: (4 - b.count % 4) % 4)
        self.init(base64Encoded: b)
    }
    var base64URLNoPad: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
