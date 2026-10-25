# chip-reader-ios

Native iPhone helper that reads the passport chip over NFC and sends it, sealed end to end, to the lawyer's console.
Same transfer as `packages/chip-link` (the `legxchip1:` QR, the `LGXC` wire format, HPKE X-Wing). It supersedes the
Android skeleton for the demo.

Flow: paste the console QR text, type document number and the two dates from the passport, tap "Read passport chip",
hold the phone on the passport (BAC/PACE, DG1, SOD, DG14, DG15, Active Authentication on the QR's 8-byte challenge),
review the sizes, "Seal and send". The post body is JSON `{sessionId, enc, ct}` (hex, base64url, base64url).

## Install on your iPhone (needs iPhone 7 or later on iOS 26, and Xcode 26)
1. `open apps/chip-reader-ios/ChipReader.xcodeproj` (regenerate with `xcodegen generate` from `project.yml` if you change it).
2. Select target ChipReader, Signing & Capabilities: tick "Automatically manage signing", pick your Apple ID Personal Team,
   and change the bundle identifier to a unique one (for example `com.yourname.legx.chipreader`).
3. "Near Field Communication Tag Reading" is in the entitlements file; Xcode adds it to your profile. A free Personal Team
   can use it on a device you own (profiles last 7 days).
4. Plug in the phone, choose it as the run destination, Run. On the phone trust the developer under Settings, General, VPN & Device Management.

Command-line compile check (no signing): `xcodebuild -project ChipReader.xcodeproj -scheme ChipReader -sdk iphoneos CODE_SIGNING_ALLOWED=NO build`.
Tests (simulator): `xcodebuild ... -scheme ChipReader -destination 'platform=iOS Simulator,name=iPhone 17' test`.
Regenerate the Node vector: `node tools/gen-vector.ts`; check a Swift-sealed bundle in Node: `node tools/gen-vector.ts open /tmp/chipreader-ios-sealed.json`.

## Tested
Compiles for device; 5 simulator tests: wire bytes equal chip-link's, QR parse, CryptoKit opens a bundle that chip-link
(`@hpke` X-Wing) sealed, chip-link opens a bundle CryptoKit sealed, MRZ check digits (ICAO specimen).

## NOT tested
A real passport (BAC/PACE, DG reads, Active Authentication on a physical chip), a real NFC session, the post to a live
console (the console has no receiving route yet, the URL is typed by hand), passports with long AA keys (set
`useExtendedMode` in `ChipReaderService.swift` if reads fail), Chip Authentication (skipped), QR scanning (text paste only).
The app does not verify the SOD; the console does (passive authentication).

## Sources
NFCPassportReader 2.3.3 https://github.com/AndyQ/NFCPassportReader ; CryptoKit HPKE X-Wing (iOS 26)
https://developer.apple.com/documentation/cryptokit ; RFC 9180 ; draft-connolly-cfrg-xwing-kem ; ICAO 9303 Part 11.
