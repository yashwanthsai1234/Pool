// Reads the passport chip over NFC and builds the transfer. BAC/PACE, DG reads and Active Authentication are done by
// AndyQ/NFCPassportReader 2.3.3 (readPassport(... aaChallenge:) signs the console's 8-byte challenge via INTERNAL AUTHENTICATE).
// Source: https://github.com/AndyQ/NFCPassportReader (Sources/NFCPassportReader/PassportReader.swift)
// Source: ICAO Doc 9303 Part 11 (BAC, PACE, Active Authentication); AID A0000002471001 is the eMRTD LDS application.
import Foundation
import NFCPassportReader

enum ChipReadError: Error { case missing(String) }

enum ChipReaderService {
    static func read(mrzKey: String, challenge: Data) async throws -> ChipData {
        let model = try await PassportReader().readPassport(
            mrzKey: mrzKey,
            tags: [.COM, .SOD, .DG1, .DG14, .DG15],
            aaChallenge: [UInt8](challenge),
            skipCA: true)   // Active Authentication is the path bound to presenceMsg (OD-23); CA is not carried
        guard let dg1 = model.getDataGroup(.DG1)?.data else { throw ChipReadError.missing("DG1") }
        guard let sod = model.getDataGroup(.SOD)?.data else { throw ChipReadError.missing("SOD") }
        let sig = model.activeAuthenticationSignature
        return ChipData(dg1: dg1, sod: sod,
                        dg14: model.getDataGroup(.DG14)?.data,
                        dg15: model.getDataGroup(.DG15)?.data,
                        aaSignature: sig.isEmpty ? nil : sig)
    }
}
