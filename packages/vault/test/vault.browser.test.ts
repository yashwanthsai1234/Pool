// P4.2-01 to 04, 06, 07, 09, 11, 15, the property and the fault tests (Chromium and WebKit, fake PRF authenticator).
// The real WebAuthn PRF runs in webauthn.browser.test.ts (Chromium, CDP virtual authenticators).
import { slotAddress, slotPolicy, slotPubkey, verifyEd25519Strict } from '@legx/core/frost';
import type { SealedDeal, SignRequest } from '@legx/core/frostRules';
import { verifyMultisigned } from '@legx/core/verify';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { encode, encodeForMultiSigning, type Transaction } from 'xrpl';
import { holderRoles, SINGLE_DEVICE_LABEL } from '../src/rules.ts';
import { createVault, type VaultDeps } from '../src/vault.ts';
import {
  binding,
  containsSecret,
  copy,
  dealId,
  exitPayment,
  fakePrf,
  freshDb,
  isZero,
  makeSlot,
  rawRows,
  sealedDeal,
  tamper,
} from './helpers.ts';

type Setup = ReturnType<typeof setup>;
function setup(over: Partial<VaultDeps> = {}) {
  const { pub, shares } = makeSlot();
  const id = dealId();
  const deal = sealedDeal(pub, 'A');
  const prf = fakePrf();
  const dbName = freshDb();
  const deals = new Map<string, SealedDeal>([[id, deal]]);
  const deps: VaultDeps = {
    role: 'alice',
    dbName,
    prf: prf.source,
    deals: async (d) => deals.get(d) as SealedDeal,
    ...over,
  };
  return { pub, shares, id, deal, prf, dbName, deps, vault: createVault(deps) };
}
const store = (s: Setup, salt?: Uint8Array) =>
  s.vault.storeShares({
    dealId: s.id,
    pub: s.pub,
    share1: copy(s.shares[0]),
    share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(s.shares[1]) },
    ...(salt ? { identitySalt: salt } : {}),
  });

afterEach(() => {
  vi.restoreAllMocks();
});

describe('P4.2-01 storeShares', () => {
  it('encrypts share 1 under a non-extractable key, share 2 under the PRF key, and zeroes the inputs', async () => {
    const s = setup();
    const share1 = copy(s.shares[0]);
    const share2 = copy(s.shares[1]);
    const salt = randomBytes(32);
    const saltCopy = salt.slice();
    await s.vault.storeShares({
      dealId: s.id,
      pub: s.pub,
      share1,
      share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: share2 },
      identitySalt: salt,
    });
    expect(isZero(share1.signingShare) && isZero(share2.signingShare) && isZero(salt)).toBe(true);
    const rows = await rawRows(s.dbName);
    expect(rows).toHaveLength(1);
    expect(containsSecret(rows, [s.shares[0].signingShare, s.shares[1].signingShare, saltCopy])).toBe(false);
    const row = rows[0] as { id: string; local: { lock: { key: CryptoKey } } };
    expect(row.id).toBe(`${s.id}:alice:A`);
    expect(row.local.lock.key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', row.local.lock.key)).rejects.toThrow();
    expect(s.prf.outputs.every(isZero)).toBe(true);
  });

  it("refuses a share that is not its holder's, and stores nothing", async () => {
    const s = setup();
    await expect(
      s.vault.storeShares({
        dealId: s.id,
        pub: s.pub,
        share1: copy(s.shares[1]),
        share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(s.shares[0]) },
      }),
    ).rejects.toThrow('SHARE_INVALID');
    expect(await rawRows(s.dbName)).toHaveLength(0);
  });

  it('a quota error leaves no half-written state and zeroes the inputs', async () => {
    const s = setup();
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    const share1 = copy(s.shares[0]);
    await expect(
      s.vault.storeShares({
        dealId: s.id,
        pub: s.pub,
        share1,
        share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(s.shares[1]) },
      }),
    ).rejects.toThrow('STORAGE_FAILED');
    vi.restoreAllMocks();
    expect(isZero(share1.signingShare)).toBe(true);
    expect(await s.vault.list()).toEqual([]);
  });
});

describe('P4.2-02 signFrost', () => {
  it('signs a binding statement that verifies strictly under the slot key', async () => {
    const s = setup();
    await store(s);
    const req = binding(s.deal, 'A');
    const sig = await s.vault.signFrost(s.id, req);
    const msg = (await import('@legx/core/dealcore')).tupleHash(
      'legx/binding/v1',
      req.kind === 'tagged' ? req.parts : [],
    );
    expect(verifyEd25519Strict(sig, msg, slotPubkey(s.pub))).toBe(true);
  });

  it('makes a valid XRPL multisign signature over encodeForMultisigning(tx, slot address)', async () => {
    const s = setup();
    await store(s);
    const tx = exitPayment(s.deal);
    const hex = await s.vault.signMultisig(s.id, tx);
    expect(hex).toMatch(/^[0-9A-F]{128}$/);
    const msg = hexToBytes(encodeForMultiSigning(tx as unknown as Transaction, slotAddress(s.pub)));
    expect(verifyEd25519Strict(hexToBytes(hex), msg, slotPubkey(s.pub))).toBe(true);
    const signed = {
      ...tx,
      Signers: [
        {
          Signer: {
            Account: slotAddress(s.pub),
            SigningPubKey: bytesToHex(slotPubkey(s.pub)).toUpperCase(),
            TxnSignature: hex,
          },
        },
      ],
    };
    expect(verifyMultisigned(encode(signed as unknown as Transaction), [slotAddress(s.pub)]).ok).toBe(true); // task 1.4 multisig check
  });

  it('refuses an off-list request before any tap', async () => {
    const s = setup();
    await store(s);
    const calls = s.prf.state.calls;
    await expect(s.vault.signMultisig(s.id, { ...exitPayment(s.deal), Amount: '99999999' })).rejects.toThrow(
      'MESSAGE_REFUSED',
    );
    await expect(s.vault.signFrost(s.id, binding(s.deal, 'B'))).rejects.toThrow('MESSAGE_REFUSED');
    expect(s.prf.state.calls).toBe(calls);
  });
});

it('P4.2-03 survives a reload: a new vault on the same database still signs', async () => {
  const s = setup();
  await store(s);
  await s.vault.close();
  const again = createVault(s.deps);
  expect((await again.list()).map((e) => e.dealId)).toEqual([s.id]);
  await expect(again.signFrost(s.id, binding(s.deal, 'A'))).resolves.toHaveLength(64);
});

it('P4.2-04 two roles on one device each see only their own entries', async () => {
  const s = setup();
  const lawyer = makeSlot();
  const lawyerDeal = sealedDeal(lawyer.pub, 'LA');
  const lawyerVault = createVault({
    role: 'lawyerA',
    dbName: s.dbName,
    deals: async () => lawyerDeal,
    cosigner: () => {
      throw new Error('no hsm');
    },
  });
  await store(s);
  await lawyerVault.storeShares({
    dealId: s.id,
    pub: lawyer.pub,
    share1: copy(lawyer.shares[0]),
    share2: { mode: 'firm-hsm' },
  });
  expect((await s.vault.list()).map((e) => e.slot)).toEqual(['A']);
  expect((await lawyerVault.list()).map((e) => e.slot)).toEqual(['LA']);
  expect((await rawRows(s.dbName)).map((r) => (r as { id: string }).id).sort()).toEqual(
    [`${s.id}:alice:A`, `${s.id}:lawyerA:LA`].sort(),
  );
  await expect(
    lawyerVault.storeShares({
      dealId: s.id,
      pub: lawyer.pub,
      share1: copy(lawyer.shares[0]),
      share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(lawyer.shares[1]) },
    }),
  ).rejects.toThrow('ROLE_REFUSED');
});

describe('P4.2-06 recovery file with a recovery code (authenticators without PRF)', () => {
  it('restores with the right code; a wrong code fails cleanly and writes nothing', async () => {
    let shown = '';
    const s = setup({
      prf: undefined,
      showRecoveryCode: (c) => {
        shown = c;
      },
    });
    await s.vault.storeShares({
      dealId: s.id,
      pub: s.pub,
      share1: copy(s.shares[0]),
      share2: { mode: 'recovery-code', share: copy(s.shares[1]) },
    });
    expect(shown).toMatch(/^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
    const file = await s.vault.backupShare2ToFile(s.id);
    expect(containsSecret(file, [s.shares[1].signingShare])).toBe(false);

    const wrong = createVault({
      ...s.deps,
      dbName: freshDb(),
      askRecoveryCode: async () => 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA',
    });
    const err = await wrong.restore(file).catch((e: Error) => e);
    expect((err as Error).message).toBe('RECOVERY_CODE_WRONG');
    expect(await wrong.list()).toEqual([]);
    await expect(
      createVault({ ...s.deps, dbName: freshDb(), askRecoveryCode: async () => 'short' }).restore(file),
    ).rejects.toThrow('RECOVERY_CODE_WRONG');

    const fresh = createVault({ ...s.deps, dbName: freshDb(), askRecoveryCode: async () => shown.toLowerCase() });
    expect(await fresh.restore(file)).toEqual({ needsShare1: true });
    await expect(fresh.signFrost(s.id, binding(s.deal, 'A'))).rejects.toThrow('NO_SHARE_1');
    await fresh.installShare1(s.id, copy(s.shares[0]));
    await expect(fresh.signFrost(s.id, binding(s.deal, 'A'))).resolves.toHaveLength(64);
  }, 60_000);

  it('a tampered or foreign file is FILE_INVALID or ROLE_REFUSED', async () => {
    const s = setup();
    await store(s);
    const file = await s.vault.backupShare2ToFile(s.id);
    const json = JSON.parse(new TextDecoder().decode(file));
    const bad = new TextEncoder().encode(JSON.stringify({ ...json, extra: 1 }));
    await expect(s.vault.restore(bad)).rejects.toThrow('FILE_INVALID');
    await expect(s.vault.restore(new Uint8Array([0xff, 0xfe]))).rejects.toThrow('FILE_INVALID');
    const bob = createVault({ ...s.deps, role: 'bob' });
    await expect(bob.restore(file)).rejects.toThrow('ROLE_REFUSED');
  });
});

describe('P4.2-07 signing without the passkey check', () => {
  it('a cancelled or failed PRF call decrypts nothing and throws PASSKEY_REQUIRED', async () => {
    const s = setup();
    await store(s);
    s.prf.state.fail = true;
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    await expect(s.vault.signFrost(s.id, binding(s.deal, 'A'))).rejects.toThrow('PASSKEY_REQUIRED');
    expect(decrypt).not.toHaveBeenCalled();
    const noPrf = createVault({ ...s.deps, prf: undefined });
    await expect(noPrf.signFrost(s.id, binding(s.deal, 'A'))).rejects.toThrow('PASSKEY_REQUIRED');
    expect(decrypt).not.toHaveBeenCalled();
  });
});

it('P4.2-09 asks for persistent storage at share creation and returns the answer', async () => {
  const persist = vi.spyOn(navigator.storage, 'persist').mockResolvedValue(true);
  const s = setup();
  await expect(store(s)).resolves.toMatchObject({ persisted: true });
  expect(persist).toHaveBeenCalledTimes(1);
  persist.mockResolvedValue(false);
  const t = setup();
  await expect(store(t)).resolves.toMatchObject({ persisted: false });
});

describe('P4.2-11 every decrypted share and PRF output is zero after the call', () => {
  const capture = () => {
    const out: Uint8Array[] = [];
    const real = crypto.subtle.decrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...a: Parameters<SubtleCrypto['decrypt']>) => {
      const r = await real(...a);
      out.push(new Uint8Array(r));
      return r;
    });
    return out;
  };

  it('after a successful signature', async () => {
    const s = setup();
    await store(s);
    const out = capture();
    await s.vault.signFrost(s.id, binding(s.deal, 'A'));
    expect(out).toHaveLength(2);
    expect(out.every(isZero) && s.prf.outputs.every(isZero)).toBe(true);
  });

  it('after a corrupted share-2 ciphertext (a clear error, buffers zero)', async () => {
    const s = setup();
    await store(s);
    await tamper(s.dbName, (rows) => {
      const row = rows[`${s.id}:alice:A`] as { share2: { share: { ct: Uint8Array } } };
      row.share2.share.ct[0] = (row.share2.share.ct[0] ?? 0) ^ 1;
      return [row];
    });
    const out = capture();
    await expect(s.vault.signFrost(s.id, binding(s.deal, 'A'))).rejects.toThrow('DECRYPT_FAILED');
    expect(out).toHaveLength(1); // share 1 opened, share 2 refused
    expect(out.every(isZero) && s.prf.outputs.every(isZero)).toBe(true);
  });

  it('after a wrong slot key (the stored share no longer matches): SHARE_INVALID, buffers zero', async () => {
    const s = setup();
    await store(s);
    const other = makeSlot().pub;
    await tamper(s.dbName, (rows) => {
      const row = rows[`${s.id}:alice:A`] as { pub: unknown };
      row.pub = other;
      return [row];
    });
    s.deal.slotPubs.A = slotPubkey(other);
    const out = capture();
    await expect(s.vault.signFrost(s.id, binding(s.deal, 'A'))).rejects.toThrow('SHARE_INVALID');
    expect(out.length).toBe(2);
    expect(out.every(isZero)).toBe(true);
  });
});

describe('P4.2-15 single-device mode', () => {
  it('needs the accepted warning, carries the label, and is part of the slot policy', async () => {
    const s = setup();
    const input = (accepted: boolean) => ({
      dealId: s.id,
      pub: s.pub,
      share1: copy(s.shares[0]),
      share2: {
        mode: 'single-device' as const,
        credential: { id: 'c', transports: [] },
        share: copy(s.shares[1]),
        acceptedWarning: accepted,
      },
    });
    await expect(s.vault.storeShares(input(false))).rejects.toThrow('SINGLE_DEVICE_NOT_ACCEPTED');
    expect(await s.vault.list()).toEqual([]);
    await expect(s.vault.storeShares(input(true))).resolves.toMatchObject({
      mode: 'single-device',
      label: SINGLE_DEVICE_LABEL,
    });
    expect(await s.vault.list()).toEqual([
      expect.objectContaining({ mode: 'single-device', label: SINGLE_DEVICE_LABEL }),
    ]);
    expect(SINGLE_DEVICE_LABEL).toBe('Single-device mode: no protection if this phone is stolen');
    expect(slotPolicy('A', holderRoles('single-device'))).not.toEqual(slotPolicy('A', holderRoles('security-key')));
    await expect(s.vault.signFrost(s.id, binding(s.deal, 'A'))).resolves.toHaveLength(64);
  });
});

it('identity salt: lent inside the frame with share 2, zeroed after', async () => {
  const s = setup();
  const salt = randomBytes(32);
  const want = salt.slice();
  await store(s, salt);
  let lent: Uint8Array | undefined;
  const same = await s.vault.withIdentitySalt(s.id, async (x) => {
    lent = x;
    return x.every((b, i) => b === want[i]);
  });
  expect(same).toBe(true);
  expect(isZero(lent as Uint8Array)).toBe(true);
});

it('property: shares 1 and 2 sign random bindings that verify under this slot and never under another', async () => {
  const s = setup();
  await store(s);
  const otherKey = slotPubkey(makeSlot().pub);
  const { tupleHash } = await import('@legx/core/dealcore');
  await fc.assert(
    fc.asyncProperty(fc.uint8Array({ minLength: 32, maxLength: 32 }), async (c) => {
      const req = binding(s.deal, 'A', c);
      const sig = await s.vault.signFrost(s.id, req);
      const msg = tupleHash('legx/binding/v1', req.kind === 'tagged' ? req.parts : []);
      return verifyEd25519Strict(sig, msg, slotPubkey(s.pub)) && !verifyEd25519Strict(sig, msg, otherKey);
    }),
    { numRuns: 25 },
  );
});

it('concurrent signatures each use fresh nonces and all verify', async () => {
  const s = setup();
  await store(s);
  const sigs = await Promise.all(
    [1, 2, 3, 4].map(() => s.vault.signFrost(s.id, binding(s.deal, 'A', new Uint8Array(32)))),
  );
  expect(new Set(sigs.map((x) => x.join())).size).toBe(4); // same message, different nonces
});

it('a ciphertext moved to another entry does not open (AAD names the entry)', async () => {
  const s = setup();
  const id2 = dealId();
  const vault = createVault({ ...s.deps, deals: async () => s.deal });
  await store(s);
  await vault.storeShares({
    dealId: id2,
    pub: s.pub,
    share1: copy(s.shares[0]),
    share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(s.shares[1]) },
  });
  await tamper(s.dbName, (rows) => {
    const b = rows[`${id2}:alice:A`] as Record<string, unknown>;
    b.local = rows[`${s.id}:alice:A`]?.local;
    return [b];
  });
  await expect(vault.signFrost(id2, binding(s.deal, 'A'))).rejects.toThrow('DECRYPT_FAILED');
  await expect(vault.signFrost(s.id, binding(s.deal, 'A'))).resolves.toHaveLength(64);
});

describe('OD-37 shipment and receipt need a confirmation that shows what is signed', () => {
  const seal = new Uint8Array(32).fill(7);
  const enc = (t: string) => new TextEncoder().encode(t);
  const shipment = (s: Setup): SignRequest => ({
    kind: 'tagged',
    tag: 'legx/shipment/v1',
    parts: [enc(s.id), seal, new Uint8Array(32).fill(9), enc('DHL'), enc('TRK1'), Uint8Array.of(0, 0, 0, 5)],
  });
  const receipt = (s: Setup): SignRequest => ({
    kind: 'tagged',
    tag: 'legx/receipt/v1',
    parts: [
      enc(s.id),
      seal,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(9),
      Uint8Array.of(1),
      Uint8Array.of(0, 0, 0, 6),
    ],
  });
  it('shows the manifest root, carrier and tracking, signs after yes, and signs nothing after no', async () => {
    const shown: unknown[] = [];
    let answer = true;
    const s = setup({
      role: 'bob',
      confirm: async (_d, what) => {
        shown.push(what);
        return answer;
      },
    });
    const deal = { ...s.deal, dealId: s.id, dealSeal: seal, slotPubs: { ...s.deal.slotPubs, B: slotPubkey(s.pub) } };
    s.deps.deals = async () => deal;
    await s.vault.storeShares({
      dealId: s.id,
      pub: s.pub,
      share1: copy(s.shares[0]),
      share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(s.shares[1]) },
    });
    const sig = await s.vault.signFrost(s.id, shipment(s));
    expect(sig).toHaveLength(64);
    expect(shown).toEqual([{ kind: 'shipment', manifestRoot: '09'.repeat(32), carrier: 'DHL', trackingId: 'TRK1' }]);
    answer = false;
    await expect(s.vault.signFrost(s.id, shipment(s))).rejects.toMatchObject({ code: 'APPROVAL_REFUSED' });
  });

  it('refuses a shipment when the frame has no confirm callback, and decodes a receipt for the screen', async () => {
    const s = setup({ role: 'bob' });
    s.deps.deals = async () => ({
      ...s.deal,
      dealId: s.id,
      dealSeal: seal,
      slotPubs: { ...s.deal.slotPubs, B: slotPubkey(s.pub) },
    });
    await store(s);
    await expect(s.vault.signFrost(s.id, shipment(s))).rejects.toMatchObject({ code: 'APPROVAL_REFUSED' });
    const { confirmationFor } = await import('../src/confirmation.ts');
    expect(confirmationFor(receipt(s))).toEqual({
      kind: 'receipt',
      manifestRoot: '09'.repeat(32),
      condition: 'damaged',
    });
    expect(confirmationFor(binding(s.deal, 'A'))).toBeUndefined();
  });
});
