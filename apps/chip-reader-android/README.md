> **SUPERSEDED for the demo by `apps/chip-reader-ios/`** (builds, tested against chip-link). This Android sketch stays as a reference only.

# chip-reader-android (skeleton, UNBUILT and UNTESTED)

A starting point for the native chip reader helper (IMPLEMENTATION 4.6, DESIGN O13). **It has never been compiled or run.**
The machine it was written on has no Android SDK, Kotlin compiler or Gradle, and disk was too tight to install them.
The JMRTD calls are written from the JMRTD Javadoc and may not match the version you pick. Treat it as a sketch, not as
evidence that the helper works. P4.6-04 (a real passport on a real phone) is still a manual test that has not been done.

What is checked: the wire format and the console side live in `packages/chip-link` (TypeScript) with a simulated
sender, and are tested. `ChipTransfer.kt` here must produce the same bytes as `packages/chip-link/src/wire.ts`.

Not done yet: the Gradle project, the manifest (NFC permission), the QR scanner, PACE with the MRZ, the HPKE X-Wing seal
(no vetted Kotlin X-Wing library was checked; options are Bouncy Castle or a small JNI/WASM wrapper, to be decided and
cross-checked against `@legx/core/pq`), the screen that shows the user what was read, and wiping the data after sending.

Sources: JMRTD https://jmrtd.org/ and https://www.javadoc.io/static/org.jmrtd/jmrtd/0.7.35/org/jmrtd/PassportService.html ;
Android IsoDep https://developer.android.com/reference/android/nfc/tech/IsoDep ;
ICAO 9303 Part 11 https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf
