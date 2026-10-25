// The deal's public data and its seal, computed by the coordinator from what each role has logged (DESIGN 5.2 P5,
// 6.6). Every role then recomputes the seal from the same data and refuses a different one (P3.2-01).
//   key.bound(slot)            -> slot public key and commitment (C_side for clients, LC_side for lawyers)
//   frost.dkg.completed(slot)  -> slotPolicy (its group key must equal the key.bound key)
//   identity.onboarded(side)   -> idMethod (read from the attestation's own `method`)
//   enrollment keys of a slot  -> pqKeyHash = tupleHash("legx/pq-keyset/v1", three ML-DSA keys in dkg role order)
//   deal row                   -> contract root, signed-contract seal, wallet address, payouts, operations accounts
import { PublicDealData } from '@legx/contracts/deal';
import { DealKey as DealKeySchema } from '@legx/contracts/records';
import type { Slot } from '@legx/contracts/values';
import { bytesToHex, dealSeal, domain, hexToBytes } from '@legx/core/dealcore';
import { fromBase64Strict, pqKeyHash } from '@legx/core/pq';
import type { Repos } from '@legx/db';
import type { DealRow } from '@legx/db/repos/deals';
import { deriveAddress } from 'xrpl';
import type { z } from 'zod';
import { ROLE_OF_SLOT } from './keys.ts';
import { type LoggedEvent, lastOf, loadLog } from './log.ts';

type DealKey = z.infer<typeof DealKeySchema>;

export type PublicDataResult =
  | { status: 'complete'; publicData: PublicDealData; dealSeal: string; domain: string }
  | { status: 'incomplete'; missing: string[] };

const SLOTS: readonly Slot[] = ['A', 'LA', 'B', 'LB'];
const decoder = new TextDecoder();

function methodOf(e: LoggedEvent | undefined): string | undefined {
  const b64 = e?.data.attestation;
  if (typeof b64 !== 'string') return undefined;
  try {
    const env = JSON.parse(decoder.decode(fromBase64Strict(b64))) as { payload: string };
    const payload = JSON.parse(decoder.decode(fromBase64Strict(env.payload))) as { method?: string };
    return payload.method;
  } catch {
    return undefined;
  }
}

export async function derivePublicData(repos: Repos, deal: DealRow, identityPolicy: string): Promise<PublicDataResult> {
  const log = await loadLog(repos, deal.deal_id);
  const keys = await repos.enrollmentKeys.listForDeal(deal.deal_id);
  const missing: string[] = [];
  const need = <T>(v: T | undefined, name: string): T | undefined => {
    if (v === undefined || v === null) missing.push(name);
    return v ?? undefined;
  };

  const bound = (s: Slot) => lastOf(log, 'key.bound', (d) => d.slot === s)?.data;
  const dkg = (s: Slot) => lastOf(log, 'frost.dkg.completed', (d) => d.slot === s)?.data;
  const pub = (s: Slot) => need(bound(s)?.xrpl_pubkey as string | undefined, `slot ${s} key`);
  const commitment = (s: Slot) => need(bound(s)?.commitment as string | undefined, `slot ${s} commitment`);
  const policy = (s: Slot) => {
    const d = dkg(s);
    if (d !== undefined && bound(s)?.xrpl_pubkey !== d.group_pub) {
      missing.push(`slot ${s} policy matches key`);
      return undefined;
    }
    return need(d?.slot_policy as string | undefined, `slot ${s} policy`);
  };
  const pqHash = (s: Slot): string | undefined => {
    const roles = dkg(s)?.roles as string[] | undefined;
    const rows = roles?.map((r) => keys.find((k) => k.slot === s && k.holder_role === r));
    if (!rows || rows.some((r) => r === undefined)) {
      missing.push(`slot ${s} pq keys`);
      return undefined;
    }
    const pubs = rows.map((r) => fromBase64Strict((r as { mldsa65_pub: string }).mldsa65_pub)) as [
      Uint8Array,
      Uint8Array,
      Uint8Array,
    ];
    return pubs.some((p) => !p) ? undefined : bytesToHex(pqKeyHash(pubs));
  };
  const method = (side: 'A' | 'B') =>
    need(methodOf(lastOf(log, 'identity.onboarded', (d) => d.side === side)), `idMethod ${side}`);

  const candidate = {
    contractRoot: need(deal.contract_root.replace(/^0+$/, '') || undefined, 'contract root'),
    signedContractSeal: need(deal.signed_contract_seal ?? undefined, 'signed contract seal'),
    walletAddress: need(deal.shell_address ?? undefined, 'wallet address'),
    xPubA: pub('A'),
    xPubB: pub('B'),
    commitmentA: commitment('A'),
    commitmentB: commitment('B'),
    idMethodA: method('A'),
    idMethodB: method('B'),
    identityPolicy,
    lawyerPubA: pub('LA'),
    lawyerPubB: pub('LB'),
    lawyerCommitmentA: commitment('LA'),
    lawyerCommitmentB: commitment('LB'),
    lawyerOpsA: need(deal.lawyer_ops_a ?? undefined, 'operations account A'),
    lawyerOpsB: need(deal.lawyer_ops_b ?? undefined, 'operations account B'),
    releaserAccount: need(deal.releaser_account ?? undefined, 'releaser account'),
    slotPolicyA: policy('A'),
    slotPolicyLA: policy('LA'),
    slotPolicyB: policy('B'),
    slotPolicyLB: policy('LB'),
    pqKeyHashA: pqHash('A'),
    pqKeyHashLA: pqHash('LA'),
    pqKeyHashB: pqHash('B'),
    pqKeyHashLB: pqHash('LB'),
    signerAccounts: SLOTS.map((s) => bound(s)?.xrpl_pubkey as string | undefined).map((k) =>
      k === undefined ? undefined : deriveAddress(k),
    ),
    quorum: 4,
    payoutA: deal.payout_a,
    payoutB: deal.payout_b,
  };
  if (missing.length > 0) return { status: 'incomplete', missing: [...new Set(missing)].slice(0, 29) };
  const parsed = PublicDealData.safeParse(candidate);
  if (!parsed.success)
    return {
      status: 'incomplete',
      missing: [...new Set(parsed.error.issues.map((i) => i.path.join('.') || 'deal'))].slice(0, 29),
    };
  const seal = dealSeal(parsed.data);
  return {
    status: 'complete',
    publicData: parsed.data,
    dealSeal: bytesToHex(seal),
    domain: bytesToHex(domain(hexToBytes(parsed.data.contractRoot), seal)).toUpperCase(),
  };
}

/** The `DealKey` of each role that has logged all of its parts, in role order (`deals.keys`). Built from the log. */
export async function dealKeys(repos: Repos, dealId: string): Promise<DealKey[]> {
  const log = await loadLog(repos, dealId);
  const keys = await repos.enrollmentKeys.listForDeal(dealId);
  const out: DealKey[] = [];
  for (const slot of SLOTS) {
    const role = ROLE_OF_SLOT[slot];
    const bound = lastOf(log, 'key.bound', (d) => d.slot === slot)?.data;
    const dkg = lastOf(log, 'frost.dkg.completed', (d) => d.slot === slot)?.data;
    const roles = dkg?.roles as string[] | undefined;
    const holders = roles?.map((r) => keys.find((k) => k.slot === slot && k.holder_role === r));
    if (!bound || !dkg || !holders || holders.some((h) => h === undefined)) continue;
    const pubs = holders.map((h) => fromBase64Strict((h as { mldsa65_pub: string }).mldsa65_pub)) as [
      Uint8Array,
      Uint8Array,
      Uint8Array,
    ];
    if (pubs.some((p) => !p)) continue;
    const base = {
      role,
      xrpl_pubkey: bound.xrpl_pubkey,
      xrpl_account: deriveAddress(bound.xrpl_pubkey as string),
      commitment: bound.commitment,
      binding_sig: bound.binding_sig,
      slot_policy: dkg.slot_policy,
      pq_key_hash: bytesToHex(pqKeyHash(pubs)),
    };
    let candidate: unknown;
    if (slot === 'A' || slot === 'B') {
      const m = methodOf(lastOf(log, 'identity.onboarded', (d) => d.side === slot));
      candidate = { ...base, id_method: m };
    } else {
      const signed = lastOf(log, 'contract.lawyer_signed', (d) => d.role === slot)?.data;
      const ops = lastOf(log, 'ops.bound', (d) => d.role === slot)?.data;
      candidate = {
        ...base,
        contract_sig: signed?.contract_sig,
        ops_account: ops?.ops_account,
        ops_pub: ops?.ops_pub,
        ops_bind_sig_ops: ops?.sig_ops,
        ops_bind_sig_lawyer: ops?.sig_lawyer,
      };
    }
    const parsed = DealKeySchema.safeParse(candidate);
    if (parsed.success) out.push(parsed.data);
  }
  return out;
}
