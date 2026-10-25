// Test support for task 4.9: seed capture (the vault draws its seeds with getRandomValues), raw-row tampering, and a
// slot ready for the post-quantum binding.
import type { PqBinding } from '@legx/contracts/records';
import { verifyEd25519Strict } from '@legx/core/frost';
import type { SignRequest } from '@legx/core/frostRules';
import { fromBase64Strict, mldsaSign, pqKeygen, pqKeyHash, verifyPqBinding } from '@legx/core/pq';
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { vi } from 'vitest';
import type { z } from 'zod';
import { pqKeys } from '../../src/pq/keys.ts';
import { createVault } from '../../src/vault.ts';
import { copy, dealId, fakePrf, freshDb, makeSlot, sealedDeal } from '../helpers.ts';

/** Spies on `crypto.getRandomValues` (calling through) and keeps every 32-byte output: the buffers and copies. */
export function captureSeeds() {
  const buffers: Uint8Array[] = [];
  const copies: Uint8Array[] = [];
  const real = crypto.getRandomValues.bind(crypto);
  vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(a: T): T => {
    const out = real(a as never) as T;
    if (out instanceof Uint8Array && out.length === 32) {
      buffers.push(out);
      copies.push(out.slice());
    }
    return out;
  });
  return { buffers, copies };
}

/** Rewrites one row of the `enrollment` store in place. */
export async function tamperRow(dbName: string, id: string, edit: (row: Record<string, unknown>) => void) {
  const db = await new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open(dbName);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  await new Promise((resolve) => {
    const t = db.transaction('enrollment', 'readwrite');
    const q = t.objectStore('enrollment').get(id);
    q.onsuccess = () => {
      const row = q.result as Record<string, unknown>;
      edit(row);
      t.objectStore('enrollment').put(row);
    };
    t.oncomplete = resolve;
  });
  db.close();
}

/**
 * A client slot A ready for the binding: a FROST slot in the phone's vault (shares 1 and 2, fake PRF), the phone's and
 * the second authenticator's vault ML-DSA-65 keys (separate databases), and the recovery agent's key (core keygen).
 * `server` is the mocked coordinator: it accepts only a binding that core verifies, then emits `pq.bound`.
 */
export async function bindingWorld() {
  const { pub, shares } = makeSlot();
  const id = dealId();
  const deal = { ...sealedDeal(pub, 'A'), dealSeal: randomBytes(32) };
  const prf = fakePrf();
  const phoneDb = freshDb();
  const vault = createVault({ role: 'alice', dbName: phoneDb, prf: prf.source, deals: async () => deal });
  await vault.storeShares({
    dealId: id,
    pub,
    share1: copy(shares[0]),
    share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(shares[1]) },
  });
  const phoneKeys = pqKeys({ role: 'alice', dbName: phoneDb });
  const secondDb = freshDb();
  const secondKeys = pqKeys({ role: 'alice', dbName: secondDb });
  const [p, s] = [await phoneKeys.create(id), await secondKeys.create(id)];
  const agent = pqKeygen();
  const pinned = [
    { keyId: 'phone#ml-dsa-65', mlDsa65: p.mlDsa65 },
    { keyId: 'second#ml-dsa-65', mlDsa65: s.mlDsa65 },
    { keyId: 'agent#ml-dsa-65', mlDsa65: agent.publicKey },
  ] as const;
  const seal = {
    dealSeal: deal.dealSeal,
    slotPub: deal.slotPubs.A,
    pqKeyHash: pqKeyHash([p.mlDsa65, s.mlDsa65, agent.publicKey]),
  };
  const events: { kind: 'pq.bound'; binding: z.infer<typeof PqBinding> }[] = [];
  const server = vi.fn(async (b: z.infer<typeof PqBinding>) => {
    const res = verifyPqBinding(
      {
        dealSeal: hexToBytes(b.deal_seal),
        slotPub: hexToBytes(b.slot_pub),
        pqKeyHash: hexToBytes(b.pq_key_hash),
        holderSigs: b.holder_sigs.map((h) => ({ keyId: h.key_id, sig: fromBase64Strict(h.sig) as Uint8Array })),
        crossSig: hexToBytes(b.cross_sig),
      },
      seal,
      pinned,
      (pub, m, sig) => verifyEd25519Strict(sig, m, pub),
    );
    if (!res.ok) throw new Error(res.code);
    events.push({ kind: 'pq.bound', binding: b });
  });
  return {
    id,
    phoneDb,
    secondDb,
    xwingPubs: [p.xwing, s.xwing],
    pub,
    shares,
    deal,
    prf,
    vault,
    seal,
    pinned,
    events,
    server,
    offer: { dealSeal: seal.dealSeal, slotPub: seal.slotPub, holders: pinned },
    phone: await phoneKeys.half(id, pinned[0].keyId),
    second: await secondKeys.half(id, pinned[1].keyId),
    agentSign: (msg: Uint8Array) => ({
      keyId: pinned[2].keyId,
      sig: mldsaSign('ml-dsa-65', agent.secretKey, msg, 'legx/pq-binding/v1'),
    }),
    crossSign: (req: SignRequest) => vault.signFrost(id, req),
  };
}
