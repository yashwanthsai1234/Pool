# UX bar for the product demo (binding for the UX agents)

The audience is hackathon judges watching on a projector, plus two people holding phones. They must understand each screen in 3 seconds.

## Principles
1. **One primary action per screen.** It is big, full-width on phones, and always in the same place (the bottom of the screen on phones).
2. **Always say whose turn it is.** Use a banner: "Your turn: fund the escrow" or "Waiting for Bob to sign the shipment". Never leave a dead screen.
3. **Plain language, not jargon.** "Set up my keys", not "FROST DKG". The technical detail goes behind an "i" tooltip or a "Details" disclosure.
4. **Names first, IDs second.** "Alice" is big. `rid_k3x9…` is a small monospace chip with a copy button, and the full fingerprint is in the tooltip.
5. **Instant feedback.**
   - Pressed: a spinner on the button, with the button disabled.
   - Success: a green check with a short message ("Escrow funded: 25 XRP locked"), plus a link to the transaction.
   - Error: what happened and what to do, in human words. Never show raw JSON.
6. **The flow moves you forward.** Register goes straight to My deals. Creating a deal goes straight to that deal's detail page. A finished deal shows a celebratory "Released" state.
7. **Empty states and loading.** "No deals yet: the deal page creates one." Skeletons while loading, never a blank screen.
8. **Visual system.**
   - one font scale (16 / 20 / 28 / 40), and 8 px spacing;
   - rounded cards with a soft border;
   - status chips: Locked (amber, padlock icon), Released (green), Failed (red);
   - the dots artifact: big, readable from 5 m, with the current step pulsing;
   - dark and light themes both work;
   - inline SVG icons only (no new dependencies).
9. **Phones:** 390 px wide first, touch targets of at least 48 px, the action button pinned at the bottom with a safe-area inset, and no horizontal scroll.
10. **Projector (`/present`, `/deals`):** large type, high contrast, and the escrow card always visible.
11. **Accessibility:** axe clean, visible focus, and the reduced-motion preference respected.
