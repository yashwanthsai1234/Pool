# doc-sync (status)

**State:** done. Edited only DESIGN.md, IMPLEMENTATION.md, build/ISSUES.md and this file. No tests apply (docs only).

## DESIGN.md vs OD-21 to OD-33
Already present: OD-21 (6.15 "Signer bound to the seal"), OD-22, OD-23 (6.15), OD-29 (6.17 `distinct_tag`).
Added: OD-24 (6.13 noble verify only), OD-25 and OD-32 (6.10 onboarding: `zk-disclosure` box, verification in the lawyer's console), OD-26 (6.4 single-device recovery code), OD-27 and OD-30 (4.2), OD-28 (5.4 lawyer replacement), OD-31 (8.10 observer), OD-33 (5.2 and 6.4 allow-list, 7.3 row 5f).
Also from ISSUES: 5g signing (5.2, 7.3), stranger trust line (5.2), T-I-12 demo profile (12.2).

## IMPLEMENTATION.md
Layout (4.8): chip-link, tests/system, tests/break-it, tools/differential, tools/mutation. "As built" notes: 1.15, 2.8, 2.9 (ZK nightly), 4.6 (Android skeleton), 5.3, 5.7, phase 6. P2.9-02 code name now `ZK_RESULT_MISSING`.

## ISSUES.md
fixed (doc): I-10, I-2.5-e, I-2.5-f, I-2.6-c, I-2.8-a, I-2.8-c, I-2.9-c, I-2.9-d.
Left open: I-2.9-f (see new I-DOC-1: code sets `face_match_passed` false when face match is off, DESIGN 6.15 expects true). I-E3 is design-accepted info; untouched.

## Known gaps
I did not check that every existing DESIGN reference to OD-31 key registration matches code. Row 5b "four slots" in the 2.8 test differs from the table (shell signs 5b); I did not state it in DESIGN.
