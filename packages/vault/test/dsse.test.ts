// The evidence signer's allow-list is a pure function: it accepts exactly the PAE of an evidence statement of the named deal.
import { ATTEST_PAYLOAD_TYPE, PAYLOAD_TYPE, pae } from '@legx/core/evidence';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { dsseDealOf } from '../src/dsse.ts';

const DEAL = '0192f1a0-7b3c-7d4e-8f00-0000000000a1';
const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const event = (extra: object) => enc({ predicate: { deal_id: DEAL, ...extra } });
const attest = (extra: object) => enc({ deal_id: DEAL, ...extra });

describe('dsseDealOf', () => {
  it('accepts an event and an attestation of the deal, with any other fields', () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string({ maxLength: 8 }), fc.string({ maxLength: 20 })), (extra) => {
        const x = { ...extra, kind: 'k' };
        expect(dsseDealOf(pae(PAYLOAD_TYPE, event(x)), DEAL)).toBe(true);
        expect(dsseDealOf(pae(ATTEST_PAYLOAD_TYPE, attest(x)), DEAL)).toBe(true);
      }),
    );
  });

  it('refuses every proper prefix, and any byte appended', () => {
    const msg = pae(PAYLOAD_TYPE, event({ kind: 'k' }));
    fc.assert(
      fc.property(fc.integer({ min: 0, max: msg.length - 1 }), fc.integer({ min: 0, max: 255 }), (cut, b) => {
        expect(dsseDealOf(msg.slice(0, cut), DEAL)).toBe(false);
        expect(dsseDealOf(new Uint8Array([...msg, b]), DEAL)).toBe(false);
      }),
    );
  });

  it('reads the deal where its payload type puts it: an event with deal_id at the top level is not of this deal', () => {
    expect(dsseDealOf(pae(PAYLOAD_TYPE, attest({})), DEAL)).toBe(false);
    expect(dsseDealOf(pae(ATTEST_PAYLOAD_TYPE, event({})), DEAL)).toBe(false);
  });

  it('refuses arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (b) => {
        expect(dsseDealOf(b, DEAL)).toBe(false);
      }),
    );
  });
});
