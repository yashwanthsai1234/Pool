// The BAC/PACE access key: documentNumber (padded to 9 with '<') + check digit, birth date YYMMDD + check, expiry YYMMDD + check.
// Source: ICAO Doc 9303 Part 11 section 4.3 / Part 3 check digits (weights 7,3,1)
import Foundation

enum Mrz {
    static func checkDigit(_ s: String) -> Int {
        let w = [7, 3, 1]
        var sum = 0
        for (i, c) in s.enumerated() {
            let v: Int
            if let d = c.wholeNumberValue, c.isASCII { v = d }
            else if c == "<" { v = 0 }
            else if let a = c.asciiValue, a >= 65, a <= 90 { v = Int(a) - 55 }
            else { v = 0 }
            sum += v * w[i % 3]
        }
        return sum % 10
    }

    /// `birth` and `expiry` are YYMMDD.
    static func key(documentNumber: String, birth: String, expiry: String) -> String {
        let doc = documentNumber.uppercased().padding(toLength: max(9, documentNumber.count), withPad: "<", startingAt: 0)
        return doc + String(checkDigit(doc)) + birth + String(checkDigit(birth)) + expiry + String(checkDigit(expiry))
    }
}
