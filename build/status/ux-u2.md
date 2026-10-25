# ux-u2
Done: /deals form (2 columns, pickers with RidChip, same-person refusal, XRP suffix, PDF dropzone with name/size/SHA-256, goes straight to the new deal's detail), tabs with counts/skeleton/empty state, locked detail (escrow card, dots, timeline), released detail (sections, gate grid, tx links, All metadata), /present projector layout.
Fixes: useDealStages polls GET /api/demo/deals/:id every 1.5 s until released (no ws); pdfHref prefixes /api. /deals rows and detail use the hook; /me (party) still uses LiveProgress and must switch to useDealStages from routes/present/-stages.tsx.
Tests: deals + present browser tests pass (incl. dots green after poll, axe). Screenshots (1440, 1920): build/tmp/ux/u2-*.png (present not shot).
