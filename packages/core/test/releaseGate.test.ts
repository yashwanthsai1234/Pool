// Task 1.12: the release gate (DESIGN 6.17). T-U-18a/b, T-P-07, T-A-27 to T-A-30, T-A-28b, P1.12-01 to 12.
// The world in helpers/gate.ts is built with the real primitives (FROST DKG, ML-DSA-65, hybrid envelopes, a signed
// NFTokenMint blob); each attack row changes one input and re-signs what a real attacker could re-sign.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LegxEvent } from '@legx/contracts/events';
import { Finding as FindingSchema, GATE_CODES } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { attestConfig } from '../src/attest.ts';
import { leafHashOf } from '../src/evidence.ts';
import { messageAllowed } from '../src/frostRules.ts';
import { signHybrid } from '../src/hybridEnvelope.ts';
import { lsf } from '../src/lockcheck.ts';
import { fromBase64Strict, pqKeygen } from '../src/pq.ts';
import {
  buildGatePassedRecord,
  checkRelease,
  type GateCode,
  gateMemo,
  type ReleaseInput,
  verifyGatePassedRecord,
} from '../src/releaseGate.ts';
import { buildSignedContractSeal, MINT_MEMO_TYPE, nftUri } from '../src/signedContract.ts';
import {
  ANCHOR,
  bytes,
  DEAL_ID,
  h32,
  type Json,
  LEDGER,
  makeWorld,
  mutable,
  NOW,
  nftokenId,
  OPS,
  TRUST,
  type World,
  zkOnboardChecks,
  zkReleaseChecks,
} from './helpers/gate.ts';
import { pyVector } from './helpers/pyref.ts';

const T = 120_000;
const failing = (i: ReleaseInput) => checkRelease(i).filter((f) => !f.ok);
const failingCodes = (i: ReleaseInput) => failing(i).map((f) => f.code);
const detailOf = (i: ReleaseInput, code: GateCode) => checkRelease(i).find((f) => f.code === code)?.detail;
const passes = (i: ReleaseInput) => failing(i).length === 0;
const EVENT_FIELDS = {
  event_id: '0192f1a0-7b3c-7d4e-8f00-0000000000ff',
  seq: 40,
  occurred_at: '2026-10-24T13:00:00Z',
  prev_hash: h32(0x21),
  payload_commitment: h32(0x22),
};

let w: World;
beforeAll(async () => {
  w = await makeWorld();
}, T);

/** One attack row: change only this code's input (`change` may re-sign records), then the codes that must fail. */
// biome-ignore lint/suspicious/noExplicitAny: attack rows rewrite arbitrary parts of a copied input
type Mut = any;
type Row = [GateCode, string, (i: Mut, w: World) => void | Promise<void>, GateCode[]];
const ROWS: Row[] = [
  [
    'LOCK_OK',
    'the setup key is left on',
    (i) => {
      i.ledger.account.Flags &= ~lsf.DisableMaster;
    },
    ['LOCK_OK'],
  ],
  [
    'CONTRACT_SEAL_OK',
    'the mint is not validated',
    (i) => {
      i.ledger.mintTx.validated = false;
    },
    ['CONTRACT_SEAL_OK'],
  ],
  [
    'PASSPORT_A_OK',
    'the presence signature is by another key',
    async (i, w) => {
      i.records.passport.A = await w.passport('A', { presence_sig: '11'.repeat(64) });
    },
    ['PASSPORT_A_OK'],
  ],
  [
    'PASSPORT_B_OK',
    'the anchor is not in validated history',
    async (i, w) => {
      i.records.passport.B = await w.passport('B', { ledger_anchor: { ...ANCHOR, ledger_index: 12345 } });
    },
    ['PASSPORT_B_OK'],
  ],
  [
    'BAR_A_OK',
    'the bar verification is not active',
    async (i, w) => {
      i.records.bar.LA = await w.bar('LA', { status: 'not_active' });
    },
    ['BAR_A_OK'],
  ],
  [
    'BAR_B_OK',
    'the link names another bar commitment',
    async (i, w) => {
      i.records.bar.LB = await w.bar('LB', {}, { bar_commitment: h32(0x55) });
    },
    ['BAR_B_OK'],
  ],
  [
    'ATTORNEY_CREDENTIAL_A_OK',
    'the only credential is of another type (missing)',
    (i, w) => {
      i.ledger.credentials[0] = w.credential('LA', { CredentialType: '41' });
    },
    ['ATTORNEY_CREDENTIAL_A_OK'],
  ],
  [
    'ATTORNEY_CREDENTIAL_B_OK',
    'the credential is not accepted',
    (i, w) => {
      i.ledger.credentials[1] = w.credential('LB', { Flags: 0 });
    },
    ['ATTORNEY_CREDENTIAL_B_OK'],
  ],
  [
    'RELEASER_SEALED',
    'another account submits',
    (i) => {
      i.submitter = OPS.LA.address;
    },
    ['RELEASER_SEALED'],
  ],
  [
    'OPS_BINDINGS_OK',
    'the operations signature is over another message',
    async (i, w) => {
      i.records.opsBound.LB = await w.event('ops.bound', {
        ...w.opsData('LB'),
        sig_ops: w.opsData('LA').sig_ops,
      });
    },
    ['OPS_BINDINGS_OK'],
  ],
  [
    'ONBOARDING_OK',
    'an onboarding attestation is missing',
    (i) => {
      delete i.records.onboarding.A;
    },
    ['ONBOARDING_OK'],
  ],
  [
    'IDS_DISTINCT',
    'the deal seals C_A = C_B (a whole consistent world)',
    async (i) => {
      Object.assign(i, mutable((await makeWorld({ sameCommitment: true })).input));
    },
    ['IDS_DISTINCT'],
  ],
  [
    'IDENTITY_POLICY_OK',
    'the release method differs from the onboarding method',
    async (i, w) => {
      i.records.passport.A = await w.passport('A', { method: 'nfc-chip' });
    },
    ['PASSPORT_A_OK', 'IDENTITY_POLICY_OK'],
  ],
  [
    'PQ_BINDINGS_OK',
    'a binding has one holder signature',
    async (i, w) => {
      const d = w.pqData('B') as { binding: { holder_sigs: unknown[] } };
      d.binding.holder_sigs = d.binding.holder_sigs.slice(0, 1);
      i.records.pqBound.B = await w.event('pq.bound', d);
    },
    ['PQ_BINDINGS_OK'],
  ],
  [
    'SLOT_SETUP_OK',
    'a test signature is a copy of another pair',
    async (i, w) => {
      const tests = w.S.A.dkg.test_sigs as string[];
      i.records.dkgCompleted.A = await w.event('frost.dkg.completed', {
        ...w.S.A.dkg,
        test_sigs: [tests[0], tests[1], tests[0]],
      });
    },
    ['SLOT_SETUP_OK'],
  ],
  [
    'SHIPMENT_SIGNED_OK',
    'the shipment is signed by slot A instead of slot B (and the receipt then has no valid shipment)',
    async (i, w) => {
      i.records.shipments = [
        await w.event(
          'shipment.signed',
          w.ship.shipmentData((m) => w.S.A.sign(m)),
        ),
      ];
    },
    ['SHIPMENT_SIGNED_OK', 'RECEIPT_SIGNED_OK'],
  ],
  [
    'RECEIPT_SIGNED_OK',
    "attack 1: the receipt is forged with slot B, not Alice's slot A",
    async (i, w) => {
      i.records.receipts = [
        await w.event(
          'receipt.signed',
          w.ship.receiptData((m) => w.S.B.sign(m)),
        ),
      ];
    },
    ['RECEIPT_SIGNED_OK'],
  ],
];
const broken = async (row: Row) => {
  const i = mutable(w.input);
  await row[2](i, w);
  return i as ReleaseInput;
};

describe('T-U-18a and the DESIGN 6.17 table', () => {
  it('T-U-18a: every input good gives 17 passing blocking findings, in the DESIGN 6.17 order', () => {
    const f = checkRelease(w.input);
    expect(f.map((x) => x.code)).toEqual([...GATE_CODES]);
    expect(f.every((x) => x.ok && x.level === 'block' && x.detail === undefined)).toBe(true);
    for (const x of f) expect(FindingSchema.safeParse(x).success).toBe(true);
  });

  it('the codes are exactly the DESIGN 6.17 table, in its order', () => {
    const design = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../../DESIGN.md'), 'utf8');
    const section = design.slice(design.indexOf('### 6.17'), design.indexOf('**When all pass,**'));
    const codes = [...section.matchAll(/^\| `([A-Z_]+)`(?:, `([A-Z_]+)`)? \|/gm)].flatMap((m) =>
      m.slice(1).filter((x): x is string => x !== undefined),
    );
    expect(codes).toHaveLength(17);
    expect(checkRelease(w.input).map((x) => x.code)).toEqual(codes);
    expect(ROWS.map((r) => r[0])).toEqual(codes);
  });
});

describe('OD-37 shipment and receipt checks', () => {
  const codeOf = async (change: (i: Mut) => Promise<void>, code: GateCode): Promise<FindingSchema | undefined> => {
    const i = mutable(w.input);
    await change(i);
    return checkRelease(i).find((f) => f.code === code);
  };
  const receipt =
    (over: Parameters<World['ship']['receiptData']>[1]) =>
    async (i: Mut): Promise<void> => {
      i.records.receipts = [
        await w.event(
          'receipt.signed',
          w.ship.receiptData((m) => w.S.A.sign(m), over),
        ),
      ];
    };
  /** Replaces the stored records of one kind with what `make` returns. */
  const set =
    (key: 'shipments' | 'receipts', make: (i: Mut) => Promise<Uint8Array[] | undefined>) =>
    async (i: Mut): Promise<void> => {
      i.records[key] = await make(i);
    };
  const shipped = (over: Parameters<World['ship']['shipmentData']>[1]) =>
    set('shipments', async () => [
      await w.event(
        'shipment.signed',
        w.ship.shipmentData((m) => w.S.B.sign(m), over),
      ),
    ]);
  it.each([
    ['no receipt', set('receipts', async () => []), 'MISSING'],
    ['attack 2: a receipt for another shipment', receipt({ shipment: { trackingId: 'OTHER' } }), 'SHIPMENT_MISMATCH'],
    ['attack 2: a swapped manifest root', receipt({ root: new Uint8Array(32).fill(1) }), 'MANIFEST_MISMATCH'],
    ['a damaged receipt', receipt({ condition: 'damaged' }), 'CONDITION_DAMAGED'],
    ['a missing receipt', receipt({ condition: 'missing' }), 'CONDITION_MISSING'],
    ['a receipt before the shipment', receipt({ ledgerIndex: 90_000_089 }), 'LEDGER_BEFORE_SHIPMENT'],
  ] as const)('RECEIPT_SIGNED_OK fails on %s', async (_, change, detail) => {
    expect(await codeOf(change, 'RECEIPT_SIGNED_OK')).toMatchObject({ ok: false, detail });
  });
  it('the latest receipt counts: a later ok receipt replaces a damaged one', async () => {
    const i = mutable(w.input);
    const damaged = await w.event(
      'receipt.signed',
      w.ship.receiptData((m) => w.S.A.sign(m), { condition: 'damaged' }),
    );
    i.records.receipts = [damaged, ...i.records.receipts];
    expect(checkRelease(i).every((f) => f.ok)).toBe(true);
  });
  it.each([
    ['no shipment', set('shipments', async () => undefined), 'MISSING'],
    [
      'two shipments',
      set('shipments', async (i) => [i.records.shipments[0], i.records.shipments[0]]),
      'NOT_EXACTLY_ONE',
    ],
    ['a shipment after the gate ledger', shipped({ ledgerIndex: 90_000_101 }), 'LEDGER_AFTER_GATE'],
    ['a shipment of another deal seal', shipped({ dealSeal: new Uint8Array(32) }), 'MSG_HASH_MISMATCH'],
  ] as const)('SHIPMENT_SIGNED_OK fails on %s', async (_, change, detail) => {
    expect(await codeOf(change, 'SHIPMENT_SIGNED_OK')).toMatchObject({ ok: false, detail });
  });
});

describe('T-U-18b: break only one code input', () => {
  it.each(ROWS)(
    '%s: %s',
    async (_code, _what, _change, expected) => {
      const i = await broken(ROWS.find((r) => r[0] === _code) as Row);
      expect(failingCodes(i)).toEqual(expected);
      for (const f of failing(i)) expect(FindingSchema.safeParse(f).success).toBe(true);
    },
    T,
  );
});

describe('T-P-07: the gate passes if and only if no component is broken', () => {
  // Precomputed single-code breaks (async re-signing done once); the property picks any subset and applies them.
  const parts: { code: GateCode; apply: (i: Mut) => void }[] = [];
  beforeAll(async () => {
    const singles = ROWS.filter((r) => r[3].length === 1 && r[0] !== 'IDS_DISTINCT');
    for (const row of singles) {
      const changed = await broken(row);
      const flat = (x: ReleaseInput) => ({ ledger: x.ledger, records: x.records, submitter: x.submitter });
      const diff = flat(changed);
      parts.push({
        code: row[0],
        apply: (i: Mut) => {
          // Copy over exactly the part the row changed.
          for (const k of Object.keys(diff) as (keyof typeof diff)[]) {
            if (JSON.stringify(diff[k], replacer) !== JSON.stringify(flat(w.input)[k], replacer)) {
              i[k] = k === 'submitter' ? diff[k] : mergeChanged(i[k], diff[k], flat(w.input)[k]);
            }
          }
        },
      });
    }
  }, T);

  it(
    'random subsets of broken components',
    () => {
      fc.assert(
        fc.property(fc.subarray([...Array(parts.length).keys()]), (picked) => {
          const i = mutable(w.input);
          for (const k of picked) parts[k]?.apply(i);
          const expected = picked.map((k) => parts[k]?.code).sort();
          expect([...failingCodes(i)].sort()).toEqual(expected);
          expect(passes(i)).toBe(picked.length === 0);
        }),
        { numRuns: 25 },
      );
    },
    T,
  );
});

// Uint8Array-aware JSON, so changed byte records compare by content.
function replacer(_k: string, v: unknown) {
  return v instanceof Uint8Array ? bytesToHex(v) : v;
}
/** Copies into `into` only the keys of `changed` that differ from `base`, recursively over plain objects. */
// biome-ignore lint/suspicious/noExplicitAny: structural merge over the gate input
function mergeChanged(into: any, changed: any, base: any): any {
  if (
    typeof changed !== 'object' ||
    changed === null ||
    changed instanceof Uint8Array ||
    (Array.isArray(changed) && (!Array.isArray(base) || base.length !== changed.length)) ||
    typeof base !== 'object' ||
    base === null
  ) {
    return structuredClone(changed);
  }
  for (const k of new Set([...Object.keys(changed), ...Object.keys(base)])) {
    if (!(k in changed)) delete into[k];
    else if (JSON.stringify(changed[k], replacer) !== JSON.stringify(base[k], replacer))
      into[k] = mergeChanged(into[k], changed[k], base[k]);
  }
  return into;
}

describe('T-A-27: passport attestations', () => {
  it(
    'missing, stale or without the presence signature: the gate refuses',
    async () => {
      const missing = mutable(w.input);
      delete missing.records.passport.B;
      expect(detailOf(missing, 'PASSPORT_B_OK')).toBe('MISSING');

      const stale = mutable(w.input);
      stale.ledger.history[0].closeTime = NOW - 3601;
      expect(detailOf(stale, 'PASSPORT_A_OK')).toBe('STALE');
      expect(passes(stale)).toBe(false);
      const tight = mutable(w.input);
      tight.config.attest = attestConfig({ maxAgeSeconds: 59 });
      expect(detailOf(tight, 'PASSPORT_A_OK')).toBe('STALE');

      const noPresence = mutable(w.input);
      noPresence.records.passport.A = await w.passport('A', { presence_sig: undefined });
      expect(failingCodes(noPresence)).toEqual(['PASSPORT_A_OK']);
      expect(detailOf(noPresence, 'PASSPORT_A_OK')).toBe('PRESENCE_MISSING');
    },
    T,
  );

  it('a byte-changed stored envelope or garbage bytes fail closed', () => {
    const i = mutable(w.input);
    i.records.passport.A = utf8ToBytes('{not json');
    expect(detailOf(i, 'PASSPORT_A_OK')).toBe('INPUT_MALFORMED');
    const j = mutable(w.input);
    const env = JSON.parse(new TextDecoder().decode(j.records.passport.A));
    env.signatures[0].sig = env.signatures[1].sig;
    j.records.passport.A = bytes(env);
    expect(detailOf(j, 'PASSPORT_A_OK')).toMatch(/^ENVELOPE_INVALID:/);
  });
});

describe('T-A-28b: the releaser', () => {
  it('submitter !== releaserAccount fails RELEASER_SEALED only', () => {
    const i = mutable(w.input);
    i.submitter = OPS.LA.address;
    expect(failingCodes(i)).toEqual(['RELEASER_SEALED']);
    expect(detailOf(i, 'RELEASER_SEALED')).toBe('SUBMITTER_NOT_SEALED');
  });
  it('a second or a different DepositPreauth fails it too, with LOCK_OK (a lock input)', () => {
    const two = mutable(w.input);
    two.ledger.objects.push({
      LedgerEntryType: 'DepositPreauth',
      Account: two.deal.data.walletAddress,
      Authorize: OPS.LA.address,
    });
    expect(failingCodes(two)).toEqual(['LOCK_OK', 'RELEASER_SEALED']);
    const other = mutable(w.input);
    other.ledger.objects[1].Authorize = OPS.LA.address;
    expect(failingCodes(other)).toEqual(['LOCK_OK', 'RELEASER_SEALED']);
    expect(detailOf(other, 'RELEASER_SEALED')).toBe('PREAUTH_NOT_RELEASER');
  });
});

describe('T-A-29: the LEGX_ATTORNEY credential', () => {
  it.each<[string, (i: Mut) => void, string]>([
    [
      'missing',
      (i) => {
        i.ledger.credentials.shift();
      },
      'MISSING',
    ],
    [
      'of another type',
      (i) => {
        i.ledger.credentials[0] = w.credential('LA', { CredentialType: '41' });
      },
      'MISSING',
    ],
    [
      'not accepted',
      (i) => {
        i.ledger.credentials[0] = w.credential('LA', { Flags: 0 });
      },
      'NOT_ACCEPTED',
    ],
    [
      'expired at the close time',
      (i) => {
        i.ledger.credentials[0] = w.credential('LA', { Expiration: NOW });
      },
      'EXPIRED',
    ],
    [
      'from the wrong issuer',
      (i) => {
        i.ledger.credentials[0] = w.credential('LA', { Issuer: OPS.LB.address });
      },
      'WRONG_ISSUER',
    ],
  ])('%s', (_what, change, code) => {
    const i = mutable(w.input);
    change(i);
    expect(failingCodes(i)).toEqual(['ATTORNEY_CREDENTIAL_A_OK']);
    expect(detailOf(i, 'ATTORNEY_CREDENTIAL_A_OK')).toBe(code);
  });
  it('no Expiration passes; one good credential among bad ones passes', () => {
    const i = mutable(w.input);
    i.ledger.credentials[0] = w.credential('LA', { Expiration: undefined });
    i.ledger.credentials.push(w.credential('LA', { Flags: 0 }));
    expect(passes(i)).toBe(true);
  });
});

describe('T-A-30: the signed contract seal', () => {
  const withMint = (over: Json) => {
    const i = mutable(w.input);
    i.ledger.mintTx = w.mint(over);
    i.deal.mintTxHash = i.ledger.mintTx.hash;
    return i as ReleaseInput;
  };
  it('a URI with another seal fails', () => {
    const i = withMint({ URI: nftUri(new Uint8Array(32).fill(9)) });
    expect(failingCodes(i)).toEqual(['CONTRACT_SEAL_OK']);
    expect(detailOf(i, 'CONTRACT_SEAL_OK')).toBe('SEAL_MISMATCH');
  });
  it('a memo with another signature, a missing memo, or two memos fail', () => {
    const bad = buildSignedContractSeal(
      {
        contractRoot: hexToBytes(h32(1)),
        walletAddress: w.input.deal.data.walletAddress,
        lawyerPubA: w.S.LA.pubHex,
        lawyerPubB: w.S.LB.pubHex,
      },
      { sigLA: new Uint8Array(64).fill(1), sigLB: new Uint8Array(64).fill(2) },
    );
    const memo = (d: string) => ({ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: d } });
    expect(detailOf(withMint({ Memos: [memo(bad.memoHex)] }), 'CONTRACT_SEAL_OK')).toBe('SIG_LA_INVALID');
    expect(detailOf(withMint({ Memos: [] }), 'CONTRACT_SEAL_OK')).toBe('MEMO_MALFORMED');
    expect(detailOf(withMint({ Memos: [memo(w.sc.memoHex), memo(w.sc.memoHex)] }), 'CONTRACT_SEAL_OK')).toBe(
      'MEMO_MALFORMED',
    );
  });
  it('the NFT issuer, decoded from the NFTokenID, is not lawyerOpsA', () => {
    const i = mutable(w.input);
    i.deal.nftokenId = nftokenId(OPS.LB.address);
    i.ledger.mintTx.meta.nftoken_id = i.deal.nftokenId;
    expect(failingCodes(i)).toEqual(['CONTRACT_SEAL_OK']);
    expect(detailOf(i, 'CONTRACT_SEAL_OK')).toBe('NFT_ISSUER_NOT_OPS_A');
  });
  it('a caller memo without the mint hash is never trusted: another signed blob under the stored hash fails', () => {
    const i = mutable(w.input);
    i.ledger.mintTx.tx_blob = w.mint({ Sequence: 6 }).tx_blob;
    expect(detailOf(i, 'CONTRACT_SEAL_OK')).toBe('MINT_HASH_MISMATCH');
    const j = mutable(w.input);
    j.deal.mintTxHash = h32(3).toUpperCase();
    expect(detailOf(j, 'CONTRACT_SEAL_OK')).toBe('MINT_HASH_MISMATCH');
  });
  it.each<[string, (i: Mut) => void, string]>([
    [
      'no mint transaction',
      (i) => {
        delete i.ledger.mintTx;
      },
      'MINT_NOT_VALIDATED',
    ],
    [
      'a failed mint',
      (i) => {
        i.ledger.mintTx.meta.TransactionResult = 'tecNO_PERMISSION';
      },
      'MINT_NOT_APPLIED',
    ],
    [
      'a mint after the gate ledger',
      (i) => {
        i.ledger.mintTx.ledger_index = LEDGER.index + 1;
      },
      'MINT_NOT_APPLIED',
    ],
    [
      'meta names another NFT',
      (i) => {
        i.ledger.mintTx.meta.nftoken_id = nftokenId(OPS.LA.address, 9);
      },
      'NFT_ID_MISMATCH',
    ],
    [
      'an NFTokenID whose flags differ from the mint',
      (i) => {
        i.deal.nftokenId = nftokenId(OPS.LA.address, 9);
        i.ledger.mintTx.meta.nftoken_id = i.deal.nftokenId;
      },
      'NFT_ID_MISMATCH',
    ],
  ])('%s', (_what, change, code) => {
    const i = mutable(w.input);
    change(i);
    expect(detailOf(i, 'CONTRACT_SEAL_OK')).toBe(code);
  });
  it('a mint by another account or another transaction type fails', () => {
    const other = mutable(w.input);
    const tx = OPS.LB.wallet.sign({ TransactionType: 'AccountSet', Account: OPS.LB.address, Fee: '12', Sequence: 1 });
    other.ledger.mintTx = { ...other.ledger.mintTx, hash: tx.hash, tx_blob: tx.tx_blob };
    other.deal.mintTxHash = tx.hash;
    expect(detailOf(other, 'CONTRACT_SEAL_OK')).toBe('NOT_OPS_A_MINT');
  });
});

describe('P1.12-01: the release.gate.passed record', () => {
  const sign = (i: ReleaseInput = w.input, slot = w.S.LB) =>
    buildGatePassedRecord(i, EVENT_FIELDS, w.lawyerSigner.B, async (_env, msg) => slot.sign(msg));
  const verify = (b: Uint8Array) =>
    verifyGatePassedRecord(b, {
      deal: w.input.deal,
      keys: w.input.records.keys,
      lawyerB: w.input.records.slotHolders.LB,
      at: NOW,
    });
  const statementOf = (b: Uint8Array) => {
    const env = JSON.parse(new TextDecoder().decode(b));
    return JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload)));
  };

  it(
    'lists the ledger index and hash and the SHA-256 of every input record; both signatures verify',
    async () => {
      const { envelopeBytes, leafHash } = await sign();
      expect(bytesToHex(leafHash)).toBe(leafHashOf(envelopeBytes));
      const st = statementOf(envelopeBytes);
      expect(LegxEvent.safeParse(st).success).toBe(true);
      const gate = st.predicate.data.gate;
      expect(gate.ledger).toEqual({ ledger_index: LEDGER.index, ledger_hash: LEDGER.hash });
      expect(gate.deal_seal).toBe(bytesToHex(w.seal));
      expect(gate.findings).toEqual(checkRelease(w.input));
      const r = w.input.records;
      const expected = [
        ...(['A', 'B'] as const).flatMap((s) => [
          [`passport.verified/${s}`, r.passport[s]],
          [`zk.proof/${s}`, r.zkProof[s]],
          [`identity.onboarded/${s}`, r.onboarding[s]],
        ]),
        ...(['LA', 'LB'] as const).flatMap((s) => [
          [`bar.deal_link/${s}`, r.bar[s]?.link],
          [`bar.verification/${s}`, r.bar[s]?.verification],
          [`ops.bound/${s}`, r.opsBound[s]],
        ]),
        ...(['A', 'LA', 'B', 'LB'] as const).flatMap((s) => [
          [`pq.bound/${s}`, r.pqBound[s]],
          [`frost.dkg.completed/${s}`, r.dkgCompleted[s]],
        ]),
        ['shipment.signed', r.shipments?.[0]],
        ['receipt.signed', r.receipts?.[0]],
      ].map(([name, b]) => ({ name, sha256: bytesToHex(sha256(b as Uint8Array)) }));
      expect(gate.relied_on).toEqual(expected);
      expect(st.predicate.actor).toEqual({ role: 'lawyerB', key_id: 'LB/console/ed' });
      expect(verify(envelopeBytes)).toEqual({ ok: true });
    },
    T,
  );

  it(
    'the slot LB signature is over a message the holders allow-list accepts as a gate record',
    async () => {
      let seen: { env: Uint8Array; msg: Uint8Array } | undefined;
      await buildGatePassedRecord(w.input, EVENT_FIELDS, w.lawyerSigner.B, async (env, msg) => {
        seen = { env, msg };
        return w.S.LB.sign(msg);
      });
      const d = w.input.deal.data;
      const deal = {
        walletAddress: d.walletAddress,
        contractRoot: hexToBytes(d.contractRoot),
        dealSeal: w.seal,
        payoutA: { account: d.payoutA },
        payoutB: { account: d.payoutB },
        exitAmountDrops: '1',
        maxFeeDrops: '1',
        slotPubs: {
          A: hexToBytes(d.xPubA),
          B: hexToBytes(d.xPubB),
          LA: hexToBytes(d.lawyerPubA),
          LB: hexToBytes(d.lawyerPubB),
        },
      };
      const req = { kind: 'gate-record' as const, envelope: seen?.env as Uint8Array };
      expect(messageAllowed(req, seen?.msg as Uint8Array, deal, 'LB')).toEqual({ ok: true });
      expect(messageAllowed(req, seen?.msg as Uint8Array, deal, 'LA').ok).toBe(false);
    },
    T,
  );

  it(
    'either signature missing fails',
    async () => {
      const { envelopeBytes } = await sign();
      const env = JSON.parse(new TextDecoder().decode(envelopeBytes));
      expect(verify(bytes({ ...env, signatures: env.signatures.slice(0, 1) }))).toEqual({
        ok: false,
        code: 'ENVELOPE_INVALID:PQ_SIGNATURE_MISSING',
      });
      // Without slot_lb_sig, re-signed by lawyer B: the record no longer parses as a gate record.
      const st = statementOf(envelopeBytes);
      delete st.predicate.data.gate.slot_lb_sig;
      const noSlot = await signHybrid('application/vnd.legx.event+json;v=1', bytes(st), w.lawyerSigner.B);
      expect(verify(bytes(noSlot))).toEqual({ ok: false, code: 'NOT_A_GATE_RECORD' });
      // A slot signature over another record.
      const st2 = statementOf(envelopeBytes);
      st2.predicate.data.gate.ledger.ledger_index += 1;
      const moved = await signHybrid('application/vnd.legx.event+json;v=1', bytes(st2), w.lawyerSigner.B);
      expect(verify(bytes(moved))).toEqual({ ok: false, code: 'SLOT_SIG_INVALID' });
    },
    T,
  );

  it(
    'signed by lawyer A, for another deal, or by a slot other than LB: refused',
    async () => {
      const byA = await buildGatePassedRecord(w.input, EVENT_FIELDS, w.lawyerSigner.A, async (_e, m) => w.S.LB.sign(m));
      expect(verify(byA.envelopeBytes)).toEqual({ ok: false, code: 'WRONG_SIGNER' });
      await expect(sign(w.input, w.S.LA)).rejects.toThrow('SLOT_LB_SIG_INVALID');
      const { envelopeBytes } = await sign();
      const other = verifyGatePassedRecord(envelopeBytes, {
        deal: { ...w.input.deal, id: '0192f1a0-7b3c-7d4e-8f00-0000000000b2' },
        keys: w.input.records.keys,
        lawyerB: w.input.records.slotHolders.LB,
        at: NOW,
      });
      expect(other).toEqual({ ok: false, code: 'WRONG_DEAL' });
      expect(verify(utf8ToBytes('garbage'))).toEqual({ ok: false, code: 'MALFORMED' });
    },
    T,
  );

  it('a blocked gate builds no record', async () => {
    const i = mutable(w.input);
    i.submitter = OPS.LA.address;
    await expect(sign(i)).rejects.toThrow('GATE_BLOCKED');
  });
});

describe('P1.12-02: gateMemo', () => {
  it('equals the Python reference vector (DESIGN D22)', () => {
    const v = pyVector<{ envelope: string }, { MemoType: string; MemoData: string }>('gate_memo', 'gateMemo');
    expect(gateMemo(sha256(hexToBytes(v.inputs.envelope)))).toEqual(v.output);
    expect(gateMemo(new Uint8Array(32)).MemoType).toBe(bytesToHex(utf8ToBytes('legx/release-gate/v1')).toUpperCase());
  });
  it('refuses a leaf hash that is not 32 bytes', () => {
    expect(() => gateMemo(new Uint8Array(31))).toThrow(RangeError);
  });
});

describe('P1.12-03: determinism', () => {
  it(
    'the same findings in the same order, twice, and on a copy of the input',
    async () => {
      const i = await broken(ROWS[2] as Row);
      expect(checkRelease(i)).toEqual(checkRelease(i));
      expect(checkRelease(mutable(i))).toEqual(checkRelease(i));
      expect(checkRelease(w.input)).toEqual(checkRelease(mutable(w.input)));
    },
    T,
  );
});

describe('P1.12-04 and the identity policy', () => {
  it('zkpassport for A and nfc-chip for B under "zk-or-chip" passes', () => {
    expect(w.input.deal.data.identityPolicy).toBe('zk-or-chip');
    expect(passes(w.input)).toBe(true);
  });
  it(
    'the same pair under "zk" fails PASSPORT_B_OK',
    async () => {
      const z = await makeWorld({ policy: 'zk', methodB: 'zkpassport' });
      const i = mutable(z.input);
      i.records.passport.B = await z.passport('B', { method: 'nfc-chip' });
      expect(detailOf(i, 'PASSPORT_B_OK')).toBe('METHOD_NOT_ALLOWED');
      expect(failingCodes(i)).toEqual(['PASSPORT_B_OK', 'IDENTITY_POLICY_OK']);
    },
    T,
  );

  it(
    'P1.12-07: policy "chip" with a zero-knowledge release attestation',
    async () => {
      const c = await makeWorld({ policy: 'chip', methodA: 'nfc-chip', methodB: 'nfc-chip' });
      expect(passes(c.input)).toBe(true);
      const i = mutable(c.input);
      i.records.passport.A = await c.passport('A', { method: 'zkpassport' });
      expect(failingCodes(i)).toEqual(['PASSPORT_A_OK', 'IDENTITY_POLICY_OK']);
      expect(detailOf(i, 'PASSPORT_A_OK')).toBe('METHOD_NOT_ALLOWED');
      expect(detailOf(i, 'IDENTITY_POLICY_OK')).toBe('A:METHOD_NOT_ALLOWED');
    },
    T,
  );

  it(
    'P1.12-07 and P1.12-08: a release method that differs from the sealed idMethod and the onboarding method',
    async () => {
      const i = await broken(ROWS[12] as Row);
      expect(detailOf(i, 'PASSPORT_A_OK')).toBe('METHOD_MISMATCH');
      expect(detailOf(i, 'IDENTITY_POLICY_OK')).toBe('A:METHOD_DIFFERS_FROM_ONBOARDING');
    },
    T,
  );
});

describe('P1.12-05: ONBOARDING_OK', () => {
  it.each<[string, (i: Mut) => Promise<void>, string]>([
    [
      'missing',
      async (i) => {
        delete i.records.onboarding.B;
      },
      'B:MISSING',
    ],
    [
      "signed by the other side's lawyer",
      async (i) => {
        i.records.onboarding.A = await w.onboarding('A', {}, 'B');
      },
      'A:WRONG_SIGNER',
    ],
    [
      'a method other than the sealed idMethod',
      async (i) => {
        i.records.onboarding.A = await w.onboarding('A', { method: 'nfc-chip' });
      },
      'A:METHOD_MISMATCH',
    ],
    // OD-2: the gate has no salt; it trusts the lawyer's statement of C_side, so the zk case is "states another C_side".
    [
      'it states another C_side',
      async (i) => {
        i.records.onboarding.A = await w.onboarding('A', { commitment: h32(0x56) });
      },
      'A:COMMITMENT_MISMATCH',
    ],
    [
      'its trust record fails the production rules',
      async (i) => {
        i.records.onboarding.A = await w.onboarding('A', {
          checks: { ...zkOnboardChecks('A', '1234567890'), trust: { ...TRUST, dev_mode: true } },
        });
      },
      'A:DEVMODE_REFUSED',
    ],
  ])(
    '%s: only ONBOARDING_OK fails',
    async (_what, change, code) => {
      const i = mutable(w.input);
      await change(i);
      expect(failingCodes(i)).toEqual(['ONBOARDING_OK']);
      expect(detailOf(i, 'ONBOARDING_OK')).toBe(code);
    },
    T,
  );
});

describe('P1.12-06: IDS_DISTINCT', () => {
  it(
    'C_A equals C_B: only IDS_DISTINCT fails',
    async () => {
      const i = await broken(ROWS[11] as Row);
      expect(detailOf(i, 'IDS_DISTINCT')).toBe('COMMITMENTS_EQUAL');
    },
    T,
  );
  it(
    'both zero-knowledge, the same identifier with different salts: only IDS_DISTINCT fails; different people pass',
    async () => {
      const same = await makeWorld({ methodB: 'zkpassport', identifiers: { A: '424242', B: '424242' } });
      expect(failingCodes(same.input)).toEqual(['IDS_DISTINCT']);
      expect(detailOf(same.input, 'IDS_DISTINCT')).toBe('IDENTIFIERS_EQUAL');
      const diff = await makeWorld({ methodB: 'zkpassport', identifiers: { A: '424242', B: '434343' } });
      expect(passes(diff.input)).toBe(true);
      // An unreadable onboarding record leaves nothing to compare; ONBOARDING_OK blocks it.
      const i = mutable(same.input);
      delete i.records.onboarding.B;
      expect(failingCodes(i)).toEqual(['ONBOARDING_OK']);
    },
    T,
  );
});

describe('P1.12-09: PQ_BINDINGS_OK', () => {
  const withBinding = async (slot: 'A' | 'LA' | 'B' | 'LB', edit: (b: Json) => void, holders?: [number, number]) => {
    const i = mutable(w.input);
    const d = w.pqData(slot, holders) as { binding: Json };
    edit(d.binding);
    i.records.pqBound[slot] = await w.event('pq.bound', d);
    return i as ReleaseInput;
  };
  it.each<[string, 'A' | 'LA' | 'B' | 'LB', (b: Json) => void, string]>([
    [
      'only one holder signature',
      'A',
      (b) => {
        b.holder_sigs = (b.holder_sigs as unknown[]).slice(0, 1);
      },
      'A:BELOW_TWO_HOLDERS',
    ],
    [
      'the same holder signing twice',
      'LA',
      (b) => {
        const s = b.holder_sigs as unknown[];
        b.holder_sigs = [s[0], s[0]];
      },
      'LA:DUPLICATE_HOLDER',
    ],
    [
      'the cross-signature missing',
      'B',
      (b) => {
        delete b.cross_sig;
      },
      'B:CROSS_SIG_MISSING',
    ],
    [
      'a cross-signature by another slot',
      'B',
      (b) => {
        b.cross_sig = (w.pqData('A') as { binding: Json }).binding.cross_sig;
      },
      'B:CROSS_SIG_INVALID',
    ],
    [
      'a pqKeyHash that differs from the seal',
      'LB',
      (b) => {
        b.pq_key_hash = h32(0x57);
      },
      'LB:PQ_KEY_HASH_MISMATCH',
    ],
    [
      'an ML-DSA signature from a key of another slot',
      'LA',
      (b) => {
        const s = b.holder_sigs as Json[];
        const other = (w.pqData('A') as { binding: { holder_sigs: Json[] } }).binding.holder_sigs[0];
        b.holder_sigs = [s[0], other];
      },
      'LA:HOLDER_KEY_UNKNOWN',
    ],
    [
      "another slot's binding",
      'A',
      (b) => {
        b.slot = 'B';
      },
      'A:MISSING',
    ],
  ])(
    '%s: only PQ_BINDINGS_OK fails',
    async (_what, slot, edit, code) => {
      const i = await withBinding(slot, edit);
      expect(failingCodes(i)).toEqual(['PQ_BINDINGS_OK']);
      expect(detailOf(i, 'PQ_BINDINGS_OK')).toBe(code);
    },
    T,
  );
  it(
    'any two distinct holders plus the cross-signature pass',
    async () => {
      for (const pair of [
        [0, 2],
        [1, 2],
        [2, 0],
      ] as [number, number][]) {
        expect(passes(await withBinding('LB', () => {}, pair))).toBe(true);
      }
    },
    T,
  );
  it(
    'a binding event for another deal or kind does not count',
    async () => {
      const i = mutable(w.input);
      i.records.pqBound.A = i.records.opsBound.LA;
      expect(detailOf(i, 'PQ_BINDINGS_OK')).toBe('A:MISSING');
      const env = JSON.parse(new TextDecoder().decode(w.input.records.pqBound.A));
      const st = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload)));
      st.subject[0].digest.sha256 = h32(2);
      const j = mutable(w.input);
      j.records.pqBound.A = bytes(await signHybrid('application/vnd.legx.event+json;v=1', bytes(st), w.lawyerSigner.A));
      expect(detailOf(j, 'PQ_BINDINGS_OK')).toBe('A:MISSING');
    },
    T,
  );
});

describe('P1.12-10: SLOT_SETUP_OK', () => {
  const withDkg = async (slot: 'A' | 'LA' | 'B' | 'LB', over: Json) => {
    const i = mutable(w.input);
    i.records.dkgCompleted[slot] = await w.event('frost.dkg.completed', { ...w.S[slot].dkg, ...over });
    return i as ReleaseInput;
  };
  const sigs = (slot: 'A' | 'LA' | 'B' | 'LB') => w.S[slot].dkg.holder_sigs as Json[];
  const tests = (slot: 'A' | 'LA' | 'B' | 'LB') => w.S[slot].dkg.test_sigs as string[];
  it.each<[string, 'A' | 'LA' | 'B' | 'LB', () => Json, string]>([
    [
      'a holder missing from the transcript signatures',
      'A',
      () => ({ holder_sigs: sigs('A').slice(0, 2) }),
      'A:TRANSCRIPT_NOT_SIGNED',
    ],
    [
      'a transcript signature by another holder',
      'B',
      () => ({ holder_sigs: [sigs('B')[0], sigs('B')[0], sigs('B')[2]] }),
      'B:TRANSCRIPT_NOT_SIGNED',
    ],
    ['another transcript hash', 'LB', () => ({ transcript_hash: h32(0x58) }), 'LB:TRANSCRIPT_NOT_SIGNED'],
    [
      'one of the three test signatures invalid',
      'B',
      () => ({ test_sigs: [tests('B')[0], tests('B')[1], tests('A')[2]] }),
      'B:TEST_SIGNATURE_INVALID',
    ],
    [
      'only two pairs test-signed (a test-sign missing)',
      'A',
      () => ({ test_sigs: tests('A').slice(0, 2) }),
      'A:TEST_SIGNATURE_INVALID',
    ],
    [
      'roles that give another slotPolicy',
      'A',
      () => ({ roles: ['phone', 'passkey-same-device', 'recovery-agent'] }),
      'A:SLOT_POLICY_MISMATCH',
    ],
    [
      'a recorded slot_policy other than the roles give',
      'LA',
      () => ({ slot_policy: h32(0x59) }),
      'LA:SLOT_POLICY_MISMATCH',
    ],
    ['another group key', 'B', () => ({ group_pub: w.S.A.pubHex }), 'B:GROUP_KEY_NOT_SEALED'],
    ['roles the slot cannot have', 'LA', () => ({ roles: ['phone', 'console', 'partner'] }), 'INPUT_MALFORMED'],
  ])(
    '%s: only SLOT_SETUP_OK fails',
    async (_what, slot, over, code) => {
      const i = await withDkg(slot, over());
      expect(failingCodes(i)).toEqual(['SLOT_SETUP_OK']);
      expect(detailOf(i, 'SLOT_SETUP_OK')).toBe(code);
    },
    T,
  );

  // I-S-G2: a lawyer slot's test signatures bind its holders' Ed25519 enrollment keys, so when they fail, that
  // lawyer's attestations have no bound signer either.
  it(
    'a lawyer slot whose test signatures fail also loses its attestations',
    async () => {
      const i = await withDkg('LB', { test_sigs: [tests('LB')[0], tests('LB')[1], tests('LA')[2]] });
      expect(failingCodes(i)).toEqual(['PASSPORT_B_OK', 'ONBOARDING_OK', 'SLOT_SETUP_OK']);
      expect(detailOf(i, 'PASSPORT_B_OK')).toBe('WRONG_SIGNER');
    },
    T,
  );
});

describe('P1.12-11 and P1.12-12: release checks and the production profile', () => {
  it.each([false, undefined])(
    'face_match_passed %s fails PASSPORT_A_OK',
    async (v) => {
      const i = mutable(w.input);
      i.records.passport.A = await w.passport('A', {
        checks: { ...zkReleaseChecks('A', w.input.records.zkProof.A), face_match_passed: v },
      });
      expect(failingCodes(i)).toEqual(['PASSPORT_A_OK']);
      expect(detailOf(i, 'PASSPORT_A_OK')).toBe('CHECK_FALSE:face_match_passed');
    },
    T,
  );

  it.each<[string, Json, string]>([
    ['Sepolia', { chain_id: 11155111 }, 'SEPOLIA_REFUSED'],
    ['a mock identifier type', { identifier_type: 'SALTED_MOCK' }, 'MOCK_IDENTIFIER_REFUSED'],
    ['dev mode', { dev_mode: true }, 'DEVMODE_REFUSED'],
  ])(
    '%s: refused in production, accepted in demo, both for onboarding and release',
    async (_what, trust, code) => {
      const t = { ...TRUST, ...trust };
      const release = mutable(w.input);
      release.records.passport.A = await w.passport('A', {
        checks: { ...zkReleaseChecks('A', w.input.records.zkProof.A), trust: t },
      });
      expect(failingCodes(release)).toEqual(['PASSPORT_A_OK']);
      expect(detailOf(release, 'PASSPORT_A_OK')).toBe(code);
      const onboard = mutable(w.input);
      onboard.records.onboarding.A = await w.onboarding('A', {
        checks: { ...zkOnboardChecks('A', '1234567890'), trust: t },
      });
      expect(failingCodes(onboard)).toEqual(['ONBOARDING_OK']);
      expect(detailOf(onboard, 'ONBOARDING_OK')).toBe(`A:${code}`);
      for (const i of [release, onboard]) {
        i.profile = 'demo';
        expect(passes(i)).toBe(true);
      }
    },
    T,
  );
});

describe('OD-34: face_match_passed is the honest result; only a demo proof in dev mode may carry false', () => {
  const noFace = async (side: 'A', trust: Json = TRUST) => {
    const i = mutable(w.input);
    i.records.passport[side] = await w.passport(side, {
      checks: { ...zkReleaseChecks(side, w.input.records.zkProof[side]), face_match_passed: false, trust },
    });
    return i;
  };
  const warnings = (i: ReleaseInput) => checkRelease(i).filter((f) => f.level === 'warn');

  it('production refuses false for zkpassport, even with a dev-mode record', async () => {
    const i = await noFace('A', { ...TRUST, dev_mode: true });
    expect(failingCodes(i)).toEqual(['PASSPORT_A_OK']);
    expect(detailOf(i, 'PASSPORT_A_OK')).toBe('CHECK_FALSE:face_match_passed');
    const plain = await noFace('A');
    expect(detailOf(plain, 'PASSPORT_A_OK')).toBe('CHECK_FALSE:face_match_passed');
    expect(warnings(plain)).toEqual([]);
  });

  it('demo with a dev-mode record passes and adds one DEMO_NO_FACE_MATCH warning that names the side', async () => {
    const i = await noFace('A', { ...TRUST, dev_mode: true });
    i.profile = 'demo';
    expect(passes(i)).toBe(true);
    expect(warnings(i)).toEqual([{ code: 'DEMO_NO_FACE_MATCH', level: 'warn', ok: true, detail: 'A' }]);
  });

  it('demo still refuses false when the record is not a dev-mode proof, and an absent field', async () => {
    const real = await noFace('A');
    real.profile = 'demo';
    expect(failingCodes(real)).toEqual(['PASSPORT_A_OK']);
    expect(detailOf(real, 'PASSPORT_A_OK')).toBe('CHECK_FALSE:face_match_passed');
    const absent = mutable(w.input);
    const { face_match_passed: _drop, ...rest } = zkReleaseChecks('A', w.input.records.zkProof.A);
    absent.records.passport.A = await w.passport('A', { checks: { ...rest, trust: { ...TRUST, dev_mode: true } } });
    absent.profile = 'demo';
    expect(detailOf(absent, 'PASSPORT_A_OK')).toBe('CHECK_FALSE:face_match_passed');
  });

  it('a true result has no warning, in either profile', () => {
    expect(warnings(w.input)).toEqual([]);
    const demo = mutable(w.input);
    demo.profile = 'demo';
    expect(warnings(demo)).toEqual([]);
  });

  it(
    'the gate record signed in demo carries the warning and still satisfies the contract',
    async () => {
      const i = await noFace('A', { ...TRUST, dev_mode: true });
      i.profile = 'demo';
      const { envelopeBytes } = await buildGatePassedRecord(i, EVENT_FIELDS, w.lawyerSigner.B, async (_e, msg) =>
        w.S.LB.sign(msg),
      );
      const env = JSON.parse(new TextDecoder().decode(envelopeBytes));
      const st = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload)));
      expect(LegxEvent.safeParse(st).success).toBe(true);
      expect(st.predicate.data.gate.findings).toContainEqual({
        code: 'DEMO_NO_FACE_MATCH',
        level: 'warn',
        ok: true,
        detail: 'A',
      });
    },
    T,
  );
});

describe('OD-21: attestation signers bound to the sealed pqKeyHash', () => {
  it(
    'a lawyer key outside the slot holders, or slot holders that do not give pqKeyHash_LA, are refused',
    async () => {
      const i = mutable(w.input);
      // Swap lawyer A's third holder for a fresh ML-DSA key: the three keys no longer hash to the sealed value.
      const fresh = pqKeygen(new Uint8Array(32).fill(0x7e));
      i.records.keys.push({
        keyId: 'rogue/pq',
        alg: 'ml-dsa-65',
        publicKey: fresh.publicKey,
        validFrom: 1,
        logged: true,
      });
      i.records.slotHolders.LA = [
        i.records.slotHolders.LA[0],
        i.records.slotHolders.LA[1],
        { ed25519: 'LA/partner/ed', mlDsa65: 'rogue/pq' },
      ];
      expect(failingCodes(i)).toEqual(['PASSPORT_A_OK', 'ONBOARDING_OK', 'PQ_BINDINGS_OK']);
      expect(detailOf(i, 'PASSPORT_A_OK')).toBe('WRONG_SIGNER');
      expect(detailOf(i, 'ONBOARDING_OK')).toBe('A:WRONG_SIGNER');
    },
    T,
  );
  it('a key ID registered twice resolves to nothing', () => {
    const i = mutable(w.input);
    const row = i.records.keys.find((k: Json) => k.keyId === 'LA/console/ed');
    i.records.keys.push({ ...row });
    expect(detailOf(i, 'PASSPORT_A_OK')).toBe('ENVELOPE_INVALID:KEY_UNKNOWN');
  });
});

describe('other rows of the rules', () => {
  it(
    'BAR: a stale verification, an anchor hash that differs from history, a missing record',
    async () => {
      const stale = mutable(w.input);
      stale.ledger.history[1].closeTime = NOW - 31 * 86_400;
      expect(failingCodes(stale)).toEqual(['BAR_A_OK', 'BAR_B_OK']);
      expect(detailOf(stale, 'BAR_A_OK')).toBe('STALE');
      const moved = mutable(w.input);
      moved.ledger.history[1].hash = h32(0x5a).toUpperCase();
      expect(detailOf(moved, 'BAR_A_OK')).toBe('ANCHOR_MISMATCH');
      const unknown = mutable(w.input);
      unknown.records.bar.LA = await w.bar('LA', { checked_at_ledger: { ...ANCHOR, ledger_index: 777 } });
      expect(detailOf(unknown, 'BAR_A_OK')).toBe('TIME_INVALID');
      const missing = mutable(w.input);
      delete missing.records.bar.LB;
      expect(failingCodes(missing)).toEqual(['BAR_B_OK']);
      expect(detailOf(missing, 'BAR_B_OK')).toBe('MISSING');
    },
    T,
  );

  it('OPS: a missing binding, a wrong role, an unvalidated account', async () => {
    const missing = mutable(w.input);
    delete missing.records.opsBound.LA;
    expect(detailOf(missing, 'OPS_BINDINGS_OK')).toBe('LA:MISSING');
    const role = mutable(w.input);
    role.records.opsBound.LA = role.records.opsBound.LB;
    expect(detailOf(role, 'OPS_BINDINGS_OK')).toBe('LA:MISSING');
    const nv = mutable(w.input);
    nv.ledger.opsAccounts.LB.validated = false;
    expect(failingCodes(nv)).toEqual(['OPS_BINDINGS_OK']);
    expect(detailOf(nv, 'OPS_BINDINGS_OK')).toBe('LB:NOT_VALIDATED');
  });

  it('LOCK: the escrow margin uses the gate ledger close time; tickets pass through', () => {
    const late = mutable(w.input);
    late.ledger.objects[4].CancelAfter = NOW + 86_399;
    expect(failingCodes(late)).toEqual(['LOCK_OK']);
    expect(detailOf(late, 'LOCK_OK')).toContain('CANCEL_AFTER_MARGIN');
    const tickets = mutable(w.input);
    tickets.deal.allowedTicketSequences = [];
    expect(passes(tickets)).toBe(true);
  });

  it(
    'a deal the seal refuses fails closed, and the gate never throws on hostile input',
    () => {
      const bad = mutable(w.input);
      bad.deal.data.releaserAccount = OPS.LA.address;
      expect(passes(bad)).toBe(false);
      fc.assert(
        fc.property(
          fc.constantFrom('passport', 'onboarding', 'opsBound', 'pqBound', 'dkgCompleted', 'bar'),
          fc.constantFrom('A', 'B', 'LA', 'LB'),
          fc.oneof(fc.uint8Array({ maxLength: 64 }), fc.constant(utf8ToBytes('{}')), fc.constant(utf8ToBytes('[]'))),
          (kind, slot, junk) => {
            const i = mutable(w.input);
            i.records[kind][slot] = kind === 'bar' ? { link: junk, verification: junk } : junk;
            const f = checkRelease(i);
            expect(f.map((x) => x.code)).toEqual([...GATE_CODES]);
            for (const x of f) expect(FindingSchema.safeParse(x).success).toBe(true);
          },
        ),
        { numRuns: 40 },
      );
      const empty = mutable(w.input);
      empty.ledger = {};
      empty.records = {
        passport: {},
        zkProof: {},
        onboarding: {},
        bar: {},
        opsBound: {},
        pqBound: {},
        dkgCompleted: {},
        keys: [],
        slotHolders: {},
      };
      // With nothing to compare, the two comparison codes pass; every code with its own input fails.
      expect(
        checkRelease(empty)
          .filter((x) => x.ok)
          .map((x) => x.code),
      ).toEqual(['IDS_DISTINCT', 'IDENTITY_POLICY_OK']);
      expect(DEAL_ID).toBe(w.input.deal.id);
    },
    T,
  );
});
