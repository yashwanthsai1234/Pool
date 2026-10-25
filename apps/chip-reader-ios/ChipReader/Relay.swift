// The post to the console's relay: POST <base>/chip-link/<session hex> with JSON {sessionId, enc, ct} (base64url).
// Source: apps/server/src/chipLink.ts
import Foundation

enum Relay {
    static func request(base: String, sessionId: Data, sealed: Sealed) throws -> URLRequest {
        let trimmed = base.trimmingCharacters(in: CharacterSet(charactersIn: "/ \n"))
        guard let url = URL(string: "\(trimmed)/chip-link/\(sessionId.hex)"), url.host != nil else { throw URLError(.badURL) }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["sessionId": sessionId.hex, "enc": sealed.enc.base64URLNoPad, "ct": sealed.ct.base64URLNoPad])
        return req
    }
}
