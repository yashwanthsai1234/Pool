// Minimal UI: scan the console QR code with the camera, enter the MRZ fields, tap the passport, review what was read, send.
// The sealed bundle is posted as JSON {sessionId, enc, ct} (base64url) to <server>/chip-link/<session> (see Relay.swift).
import SwiftUI

@main
struct ChipReaderApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @State private var qrText = ""
    @State private var postURL = ""
    @State private var docNo = ""
    @State private var birth = ""   // YYMMDD
    @State private var expiry = ""  // YYMMDD
    @State private var status = "Idle"
    @State private var read: ChipData?
    @State private var scanning = false

    var body: some View {
        Form {
            Section("Console QR code") {
                if scanning {
                    QRScanner { code in qrText = code; scanning = false; status = "QR scanned" }.frame(height: 280)
                } else {
                    Button(qrText.isEmpty ? "Scan QR code" : "Scan again") { scanning = true }
                    if !qrText.isEmpty { Text("Session \(QrContent.parse(qrText)?.sessionId.hex.prefix(8) ?? "?")...").font(.footnote) }
                }
            }
            Section("Passport (MRZ)") {
                TextField("Document number", text: $docNo).textInputAutocapitalization(.characters)
                TextField("Date of birth YYMMDD", text: $birth).keyboardType(.numberPad)
                TextField("Expiry YYMMDD", text: $expiry).keyboardType(.numberPad)
            }
            Section("Server") { TextField("https://server.example", text: $postURL).keyboardType(.URL).textInputAutocapitalization(.never) }
            Section {
                Button("Read passport chip") { Task { await readChip() } }
                if let r = read {
                    Text("DG1 \(r.dg1.count) B, SOD \(r.sod.count) B, DG14 \(r.dg14?.count ?? 0) B, DG15 \(r.dg15?.count ?? 0) B, AA \(r.aaSignature?.count ?? 0) B")
                    Button("Seal and send") { Task { await send(r) } }
                }
                Text(status).font(.footnote)
            }
        }
    }

    func readChip() async {
        guard let q = QrContent.parse(qrText.trimmingCharacters(in: .whitespacesAndNewlines)) else { status = "Bad QR text"; return }
        status = "Hold the phone on the passport..."
        do {
            read = try await ChipReaderService.read(mrzKey: Mrz.key(documentNumber: docNo, birth: birth, expiry: expiry), challenge: q.challenge)
            status = "Read OK. Review, then send."
        } catch { status = "Read failed: \(error)" }
    }

    func send(_ r: ChipData) async {
        guard let q = QrContent.parse(qrText.trimmingCharacters(in: .whitespacesAndNewlines)), !postURL.isEmpty else { status = "Bad QR or URL"; return }
        do {
            guard #available(iOS 26.0, *) else { status = "iOS 26 required (CryptoKit X-Wing)"; return }
            let sealed = try Seal.seal(try ChipTransfer.encode(r), to: q)
            let req = try Relay.request(base: postURL, sessionId: q.sessionId, sealed: sealed)
            let (_, resp) = try await URLSession.shared.data(for: req)
            status = "Sent: HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)"
            read = nil   // wipe what was read
        } catch { status = "Send failed: \(error)" }
    }
}
