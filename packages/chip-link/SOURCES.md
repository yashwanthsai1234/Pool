# @legx/chip-link sources

| URL | Used for |
|---|---|
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf | Active Authentication: RND.IFD is 8 bytes (6.1.2.1); passive authentication (5.1) |
| https://www.rfc-editor.org/rfc/rfc9180 | HPKE base mode: seal and open with `info` and `aad` |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | X-Wing KEM (through `@legx/core/pq`) |
| https://www.javadoc.io/static/org.jmrtd/jmrtd/0.7.35/org/jmrtd/PassportService.html | JMRTD `doAA` (Kotlin skeleton) |
| https://developer.android.com/reference/android/nfc/tech/IsoDep | Android IsoDep (Kotlin skeleton) |
| DESIGN.md 6.15, OD-22, OD-23 | The AA challenge is the first 8 bytes of presenceMsg |
