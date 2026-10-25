// Pinning an enrollment key (DESIGN 6.3): the key's hash enters the evidence log first, then the append-only
// `enrollment_key` row exists (the row needs the event, so no key is usable unannounced; T-U-29 at table level).
// Keys are pinned out of band, never by the coordinator's own choice: the caller is the out-of-band channel (the
// QR scan, the signed key list of a service holder, the pinned lawyer directory); `registerKey` serves the
// `keys.register` route.
import { ENROLLMENT_POP_TAG } from '@legx/contracts/api';
import type { EnrollmentKey, HybridSignatures } from '@legx/contracts/records';
import type { DealState, Role } from '@legx/contracts/values';
import { bytesToHex, hexToBytes, sha256, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { KeyNotRecorded } from '@legx/db';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { z } from 'zod';
import { isPrimaryHolder, type Principal } from './auth.ts';
import { requireDeal } from './deal.ts';
import type { CoordinatorDeps } from './deps.ts';
import { badRequest, conflict, forbidden, unprocessable } from './errors.ts';
import { ED_SUFFIX, PQ_SUFFIX, ROLE_OF_SLOT, SLOT_OF_ROLE } from './keys.ts';
import { appendCoordinatorEvent } from './statements.ts';

export async function pinEnrollmentKey(
  deps: CoordinatorDeps,
  dealId: string,
  key: z.infer<typeof EnrollmentKey>,
): Promise<'created' | 'exists'> {
  try {
    const row = await deps.db.repos.enrollmentKeys.getUsable(key.key_id);
    // The same key again is idempotent; another key under a taken id is refused (the table is append-only).
    if (
      row.deal_id !== dealId ||
      row.slot !== key.slot ||
      row.holder_role !== key.holder_role ||
      row.ed25519_pub !== key.ed25519_pub ||
      row.mldsa65_pub !== key.mldsa65_pub
    )
      throw conflict('key_id_taken', 'another key is registered under this key id');
    return 'exists';
  } catch (e) {
    if (!(e instanceof KeyNotRecorded)) throw e;
  }
  const header = await deps.ledger.validatedLedger();
  const deal = await requireDeal(deps.db.repos, dealId);
  await deps.db.transaction(async (tx) => {
    const row = await appendCoordinatorEvent(tx, deps.signer, {
      dealId,
      kind: 'enrollment.pinned',
      data: {
        key_id: key.key_id,
        slot: key.slot,
        holder_role: key.holder_role,
        key_sha256: bytesToHex(
          sha256(
            new Uint8Array([
              ...Buffer.from(key.ed25519_pub, 'hex'),
              ...(fromBase64Strict(key.mldsa65_pub) as Uint8Array),
            ]),
          ),
        ),
      },
      contractRoot: deal.contract_root,
      closeTime: header.closeTime,
      beforeAppend: async () => deal.state,
    });
    await tx.enrollmentKeys.insert({ ...key, deal_id: dealId, evidence_event_id: row.event_id });
  });
  return 'created';
}

const CLIENT_ROLES = ['phone', 'second-authenticator', 'passkey-same-device', 'recovery-agent'];
const LAWYER_ROLES = ['console', 'firm-hsm', 'partner'];
/** The client's own lawyer onboards the client's slot (DESIGN P0; OD-2). */
const OWN_LAWYER: Readonly<Record<string, string>> = { A: 'lawyerA', B: 'lawyerB' };

/** The bytes a new key signs to prove it holds both private halves (contracts ENROLLMENT_POP_TAG). */
export function enrollmentPopMessage(dealId: string, key: z.infer<typeof EnrollmentKey>): Uint8Array {
  return tupleHash(ENROLLMENT_POP_TAG, [
    utf8ToBytes(dealId),
    utf8ToBytes(key.key_id),
    utf8ToBytes(key.slot),
    utf8ToBytes(key.holder_role),
    hexToBytes(key.ed25519_pub),
    fromBase64Strict(key.mldsa65_pub) ?? new Uint8Array(),
  ]);
}

/**
 * `keys.register` (DESIGN 6.3; I-W-1): who vouches for the new key out of band, then the proof of possession, then
 * `pinEnrollmentKey`. Vouchers: a primary holder of the same slot (the QR scan between a client's devices; a console
 * pinning its firm's signed key list), the client's own lawyer (onboarding a client slot), or a lawyer directory key
 * pinning itself as the console of the slot whose operations account is its own.
 */
export async function registerKey(
  deps: CoordinatorDeps,
  principal: Principal,
  input: { dealId: string; key: z.infer<typeof EnrollmentKey>; proofOfPossession: z.infer<typeof HybridSignatures> },
): Promise<{ keyId: string; status: 'created' | 'exists' }> {
  const { dealId, key } = input;
  const lawyerSlot = key.slot === 'LA' || key.slot === 'LB';
  if (!(lawyerSlot ? LAWYER_ROLES : CLIENT_ROLES).includes(key.holder_role))
    throw badRequest(`holder role ${key.holder_role} does not belong to slot ${key.slot}`);
  const deal = await requireDeal(deps.db.repos, dealId);
  if (!vouches(deps, principal, key, deal))
    throw forbidden('not_a_voucher', 'this caller may not pin a key for that slot');

  const [ed, pq] = input.proofOfPossession;
  const msg = enrollmentPopMessage(dealId, key);
  const edSig = fromBase64Strict(ed.sig);
  const pqSig = fromBase64Strict(pq.sig);
  const pqPub = fromBase64Strict(key.mldsa65_pub);
  const ok =
    ed.keyid === `${key.key_id}${ED_SUFFIX}` &&
    pq.keyid === `${key.key_id}${PQ_SUFFIX}` &&
    edSig?.length === 64 &&
    ed25519.verify(edSig, msg, hexToBytes(key.ed25519_pub), { zip215: false }) &&
    pqSig !== undefined &&
    pqPub !== undefined &&
    mldsaVerify('ml-dsa-65', pqPub, msg, pqSig, ENROLLMENT_POP_TAG);
  if (!ok) throw unprocessable('bad_proof_of_possession', 'the new key did not sign its registration');
  return { keyId: key.key_id, status: await pinEnrollmentKey(deps, dealId, key) };
}

function vouches(
  deps: CoordinatorDeps,
  p: Principal,
  key: z.infer<typeof EnrollmentKey>,
  deal: { lawyer_ops_a: string | null; lawyer_ops_b: string | null },
): boolean {
  if (p.kind === 'deal') return SLOT_OF_ROLE[p.role] === key.slot || OWN_LAWYER[key.slot] === p.role;
  if (p.kind !== 'lawyer' || key.holder_role !== 'console') return false;
  const own = deps.lawyerKeys(p.pairId);
  const ops = key.slot === 'LA' ? deal.lawyer_ops_a : key.slot === 'LB' ? deal.lawyer_ops_b : undefined;
  return (
    own !== undefined &&
    own.opsAccount !== undefined &&
    own.opsAccount === ops &&
    bytesToHex(own.ed25519) === key.ed25519_pub &&
    fromBase64Strict(key.mldsa65_pub) !== undefined &&
    bytesToHex(own.mlDsa65) === bytesToHex(fromBase64Strict(key.mldsa65_pub) as Uint8Array)
  );
}

/** `deals.mine` (I-W-10): the deals this caller is party to, with its role in each (none for the observer). */
export async function myDeals(deps: CoordinatorDeps, p: Principal) {
  const repos = deps.db.repos;
  const one = (d: { deal_id: string; state: string }, role?: Role) => ({
    dealId: d.deal_id,
    ...(role ? { role } : {}),
    state: d.state as z.infer<typeof DealState>,
  });
  if (p.kind === 'observer') return { deals: (await repos.deals.listAll()).map((d) => one(d)) };
  if (p.kind === 'lawyer') {
    const own = deps.lawyerKeys(p.pairId);
    const byId = new Map<string, ReturnType<typeof one>>();
    if (own?.opsAccount)
      for (const d of await repos.deals.listForOps(own.opsAccount))
        byId.set(d.deal_id, one(d, d.lawyer_ops_a === own.opsAccount ? 'lawyerA' : 'lawyerB'));
    if (own)
      for (const k of await repos.enrollmentKeys.listByEd25519(bytesToHex(own.ed25519))) {
        const d = await repos.deals.get(k.deal_id);
        if (d && k.holder_role === 'console') byId.set(d.deal_id, one(d, k.slot === 'LA' ? 'lawyerA' : 'lawyerB'));
      }
    return { deals: [...byId.values()].slice(0, 200) };
  }
  if (p.kind !== 'enrolled') return { deals: [] };
  const k = await repos.enrollmentKeys.getUsable(p.pairId);
  const d = await repos.deals.get(k.deal_id);
  if (!d || !isPrimaryHolder(k.holder_role)) return { deals: [] };
  return { deals: [one(d, ROLE_OF_SLOT[k.slot as keyof typeof ROLE_OF_SLOT])] };
}
