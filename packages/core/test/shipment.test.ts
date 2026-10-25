// OD-37: the shipment and delivery receipt recipes (build/SHIP_RECEIPT.md 1 to 3).
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { mth, tupleHash } from '../src/dealcore.ts';
import {
  CONDITIONS,
  jcsItem,
  manifestRoot,
  rcptMsg,
  type ShipmentFields,
  shipMsg,
  shipmentHash,
  verifyReceipt,
  verifyShipment,
} from '../src/shipment.ts';
import { pyVectors } from './helpers/pyref.ts';

const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const DEAL_ID = '0192f1a0-7b3c-7d4e-8f00-0000000000a1';
const SEAL = new Uint8Array(32).fill(7);
const item = (sku: string, qty = 1) => ({ sku, description: `item ${sku}`, qty, weight_g: 100 * qty });
const FIRST = item('a', 2);
const ITEMS = [FIRST, item('b'), item('c', 5)];
const key = (n: number) => {
  const sk = new Uint8Array(32).fill(n);
  return { sk, pub: Uint8Array.of(0xed, ...ed25519.getPublicKey(sk)) };
};
const BOB = key(0xb0);
const ALICE = key(0xa0);

function signedShipment(over: Partial<ShipmentFields> = {}, signer = BOB.sk) {
  const f: ShipmentFields = {
    dealId: DEAL_ID,
    dealSeal: SEAL,
    manifestRoot: manifestRoot(ITEMS),
    carrier: 'DHL Express',
    trackingId: 'JD0146',
    ledgerIndex: 1000,
    ...over,
  };
  const msg = shipMsg(f);
  return {
    f,
    data: {
      manifest_root: bytesToHex(f.manifestRoot),
      carrier: f.carrier,
      tracking_id: f.trackingId,
      ledger_index: f.ledgerIndex,
      ship_msg_hash: bytesToHex(sha256(msg)),
      slot_sig: bytesToHex(ed25519.sign(msg, signer)),
    },
  };
}
const shipCtx = { dealId: DEAL_ID, dealSeal: SEAL, slotPub: BOB.pub, atLedger: 1010 };

function signedReceipt(
  over: { condition?: (typeof CONDITIONS)[number]; ledgerIndex?: number; root?: Uint8Array; hash?: Uint8Array } = {},
  signer = ALICE.sk,
) {
  const s = signedShipment();
  const f = {
    dealId: DEAL_ID,
    dealSeal: SEAL,
    shipmentHash: over.hash ?? shipmentHash(s.f),
    manifestRoot: over.root ?? s.f.manifestRoot,
    condition: over.condition ?? 'ok',
    ledgerIndex: over.ledgerIndex ?? 1005,
  };
  const msg = rcptMsg(f);
  return {
    data: {
      shipment_hash: bytesToHex(f.shipmentHash),
      manifest_root: bytesToHex(f.manifestRoot),
      condition: f.condition,
      ledger_index: f.ledgerIndex,
      rcpt_msg_hash: bytesToHex(sha256(msg)),
      slot_sig: bytesToHex(ed25519.sign(msg, signer)),
    },
  };
}
const shipped = { hash: shipmentHash(signedShipment().f), manifestRoot: manifestRoot(ITEMS), ledgerIndex: 1000 };
const rcptCtx = { dealId: DEAL_ID, dealSeal: SEAL, slotPub: ALICE.pub, atLedger: 1010, shipment: shipped };

describe('manifestRoot (RFC 8785 JCS leaves, RFC 9162 tree)', () => {
  it('serializes an item with sorted keys and no whitespace', () => {
    const b = jcsItem({ sku: 'a', description: 'b', qty: 1, weight_g: 2 });
    expect(new TextDecoder().decode(b)).toBe('{"description":"b","qty":1,"sku":"a","weight_g":2}');
  });
  it('is the RFC 9162 tree hash over the JCS bytes, in list order', () => {
    expect(manifestRoot(ITEMS)).toEqual(mth(ITEMS.map(jcsItem)));
    expect(manifestRoot([FIRST])).toEqual(sha256(Uint8Array.of(0, ...jcsItem(FIRST))));
    expect(manifestRoot([...ITEMS].reverse())).not.toEqual(manifestRoot(ITEMS));
  });
  it('a changed field of any item changes the root', () => {
    fc.assert(
      fc.property(fc.nat({ max: 2 }), fc.integer({ min: 1, max: 999 }), (i, qty) => {
        fc.pre(qty !== (ITEMS[i]?.qty ?? 0));
        const changed = ITEMS.map((x, k) => (k === i ? { ...x, qty } : x));
        expect(bytesToHex(manifestRoot(changed))).not.toBe(bytesToHex(manifestRoot(ITEMS)));
      }),
    );
  });
  it('refuses an empty manifest, extra keys, fractions, lone surrogates and out-of-range numbers', () => {
    expect(() => manifestRoot([])).toThrow();
    for (const bad of [
      { ...ITEMS[0], extra: 1 },
      { ...ITEMS[0], qty: 1.5 },
      { ...ITEMS[0], qty: 0 },
      { ...ITEMS[0], weight_g: -1 },
      { ...ITEMS[0], sku: '\ud800' },
      { ...ITEMS[0], qty: '2' },
    ])
      expect(() => manifestRoot([bad as never])).toThrow();
  });
});

describe('shipMsg, rcptMsg and the Python reference', () => {
  type V = Record<string, unknown>;
  const vs = pyVectors<V>('shipment');
  const hb = (x: unknown) => hexToBytes(String(x));
  it('has the 3 item, 3 root, 1 shipment and 3 receipt vectors', () => expect(vs).toHaveLength(10));
  it.each(vs.map((v, k) => [`${k} ${v.fn}`, v] as const))('%s', (_, v) => {
    const i = v.inputs;
    const out =
      v.fn === 'jcsItem'
        ? jcsItem(i.item as never)
        : v.fn === 'manifestRoot'
          ? manifestRoot(i.items as never)
          : v.fn === 'shipMsg'
            ? shipMsg({
                dealId: String(i.dealId),
                dealSeal: hb(i.dealSeal),
                manifestRoot: hb(i.manifestRoot),
                carrier: String(i.carrier),
                trackingId: String(i.trackingId),
                ledgerIndex: Number(i.ledgerIndex),
              })
            : rcptMsg({
                dealId: String(i.dealId),
                dealSeal: hb(i.dealSeal),
                shipmentHash: hb(i.shipmentHash),
                manifestRoot: hb(i.manifestRoot),
                condition: i.condition as never,
                ledgerIndex: Number(i.ledgerIndex),
              });
    expect(bytesToHex(out)).toBe(v.output);
  });
  it('shipMsg and rcptMsg are the spec tupleHash; shipmentHash is SHA-256(shipMsg)', () => {
    const { f } = signedShipment();
    const parts = [
      utf8ToBytes(DEAL_ID),
      SEAL,
      f.manifestRoot,
      utf8ToBytes('DHL Express'),
      utf8ToBytes('JD0146'),
      u32(1000),
    ];
    expect(shipMsg(f)).toEqual(tupleHash('legx/shipment/v1', parts));
    expect(shipmentHash(f)).toEqual(sha256(shipMsg(f)));
    const r = { dealId: DEAL_ID, dealSeal: SEAL, shipmentHash: SEAL, manifestRoot: SEAL, ledgerIndex: 9 };
    CONDITIONS.forEach((condition, n) => {
      const want = tupleHash('legx/receipt/v1', [utf8ToBytes(DEAL_ID), SEAL, SEAL, SEAL, Uint8Array.of(n), u32(9)]);
      expect(rcptMsg({ ...r, condition })).toEqual(want);
    });
  });
  it('refuses wrong-length hashes, a non-uint32 ledger index and an unknown condition', () => {
    const { f } = signedShipment();
    expect(() => shipMsg({ ...f, dealSeal: new Uint8Array(31) })).toThrow();
    expect(() => shipMsg({ ...f, manifestRoot: new Uint8Array(33) })).toThrow();
    for (const ledgerIndex of [-1, 1.5, 2 ** 32]) expect(() => shipMsg({ ...f, ledgerIndex })).toThrow();
    const r = { dealId: DEAL_ID, dealSeal: SEAL, shipmentHash: SEAL, manifestRoot: SEAL, ledgerIndex: 9 };
    expect(() => rcptMsg({ ...r, condition: 'lost' as never })).toThrow();
  });
});

describe('verifyShipment', () => {
  it('accepts a shipment signed by slot B over the rebuilt shipMsg', () => {
    const s = signedShipment();
    expect(verifyShipment(s.data, shipCtx)).toEqual({
      ok: true,
      hash: shipmentHash(s.f),
      manifestRoot: s.f.manifestRoot,
      ledgerIndex: 1000,
    });
  });
  it('refuses another key, a changed field, a wrong message hash, a ledger after the gate or too old', () => {
    expect(verifyShipment(signedShipment({}, ALICE.sk).data, shipCtx)).toMatchObject({ code: 'BAD_SIGNATURE' });
    const s = signedShipment();
    expect(verifyShipment({ ...s.data, tracking_id: 'OTHER' }, shipCtx)).toMatchObject({ code: 'MSG_HASH_MISMATCH' });
    expect(verifyShipment(s.data, { ...shipCtx, dealSeal: new Uint8Array(32) })).toMatchObject({
      code: 'MSG_HASH_MISMATCH',
    });
    expect(verifyShipment(s.data, { ...shipCtx, atLedger: 999 })).toMatchObject({ code: 'LEDGER_AFTER_GATE' });
    expect(verifyShipment(s.data, { ...shipCtx, atLedger: 1020, maxAge: 20 })).toMatchObject({ ok: true });
    expect(verifyShipment(s.data, { ...shipCtx, atLedger: 1021, maxAge: 20 })).toMatchObject({
      code: 'LEDGER_TOO_OLD',
    });
  });
  it('never throws on hostile data', () => {
    fc.assert(
      fc.property(fc.anything(), (x) => {
        expect(verifyShipment(x as never, shipCtx).ok).toBe(false);
      }),
    );
    expect(verifyShipment({ ...signedShipment().data, slot_sig: 'zz' }, shipCtx)).toMatchObject({ code: 'MALFORMED' });
  });
});

describe('verifyReceipt', () => {
  it('accepts a receipt signed by slot A, bound to the shipment', () => {
    expect(verifyReceipt(signedReceipt().data, rcptCtx)).toEqual({ ok: true, condition: 'ok', ledgerIndex: 1005 });
    expect(verifyReceipt(signedReceipt({ condition: 'damaged' }).data, rcptCtx)).toMatchObject({
      ok: true,
      condition: 'damaged',
    });
  });
  it('attack 1: a receipt forged with a key that is not slot A is refused', () => {
    expect(verifyReceipt(signedReceipt({}, BOB.sk).data, rcptCtx)).toMatchObject({ code: 'BAD_SIGNATURE' });
  });
  it('attack 2: a receipt for another shipment or a swapped manifest root is refused', () => {
    const other = sha256(utf8ToBytes('other'));
    expect(verifyReceipt(signedReceipt({ hash: other }).data, rcptCtx)).toMatchObject({ code: 'SHIPMENT_MISMATCH' });
    expect(verifyReceipt(signedReceipt({ root: other }).data, rcptCtx)).toMatchObject({ code: 'MANIFEST_MISMATCH' });
  });
  it('refuses a receipt older than the shipment, later than the gate, or with a changed condition', () => {
    expect(verifyReceipt(signedReceipt({ ledgerIndex: 999 }).data, rcptCtx)).toMatchObject({
      code: 'LEDGER_BEFORE_SHIPMENT',
    });
    expect(verifyReceipt(signedReceipt({ ledgerIndex: 1011 }).data, rcptCtx)).toMatchObject({
      code: 'LEDGER_AFTER_GATE',
    });
    const r = signedReceipt({ condition: 'missing' });
    expect(verifyReceipt({ ...r.data, condition: 'ok' }, rcptCtx)).toMatchObject({ code: 'MSG_HASH_MISMATCH' });
  });
  it('never throws on hostile data', () => {
    fc.assert(
      fc.property(fc.anything(), (x) => {
        expect(verifyReceipt(x as never, rcptCtx).ok).toBe(false);
      }),
    );
  });
});
