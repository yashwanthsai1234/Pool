// The real release gate of the composed server (DESIGN 6.17, 10.2; closes I-3.7-g). The coordinator hands it the claim a
// lawyer signed; this reads ONE validated ledger and the deal's stored records, builds the core gate's plain input, and
// runs `checkRelease` of `@legx/core/releaseGate`. Anything it cannot read makes the gate fail closed, never pass.
// Source: DESIGN.md 6.17 (the 17 codes); IMPLEMENTATION 1.12 (the gate is one pure function over one validated ledger)
import type { SignerPort } from '@legx/contracts/ports';
import { loadConfig } from '@legx/coordinator/deal';
import type { GateInput, GatePort, GateResult } from '@legx/coordinator/deps';
import { ED_SUFFIX, PQ_SUFFIX } from '@legx/coordinator/keys';
import { derivePublicData } from '@legx/coordinator/publicData';
import type { Profile } from '@legx/core/attest';
import {
  checkRelease,
  type HolderKeyIds,
  type KeyRow,
  type LedgerHeader,
  type MintTx,
  type ReleaseInput,
  type SlotHolders,
} from '@legx/core/releaseGate';
import type { Database } from '@legx/db';
import { encode } from 'xrpl';

type Slot = 'A' | 'LA' | 'B' | 'LB';
const SLOTS: readonly Slot[] = ['A', 'LA', 'B', 'LB'];
const ROLES = ['LA', 'LB'] as const;
const HOLDER_ORDERS: readonly (readonly string[])[] = [
  ['phone', 'second-authenticator', 'recovery-agent'],
  ['phone', 'passkey-same-device', 'recovery-agent'],
  ['console', 'firm-hsm', 'partner'],
];
const NOT_IN_LEDGER = [
  'hash',
  'ledger_index',
  'date',
  'inLedger',
  'validated',
  'meta',
  'metaData',
  'ctid',
  'close_time_iso',
];

export interface GateConfig {
  readonly db: Database;
  readonly profile: Profile;
  /** The verifier's own signer: its issuer account's credentials and attestation keys are what the gate trusts. */
  readonly verifierSigner: SignerPort;
  readonly verifierIssuer: string;
}

// biome-ignore lint/suspicious/noExplicitAny: ledger JSON as rippled returns it
type Json = Record<string, any>;

const text = (b: Uint8Array) => JSON.parse(new TextDecoder().decode(b)) as Json;
/** `predicate` of a stored DSSE event envelope, unverified (the gate verifies the same bytes itself). */
function predicateOf(envelope: Uint8Array): Json | undefined {
  try {
    const env = text(envelope);
    return text(new Uint8Array(Buffer.from(env.payload, 'base64'))).predicate as Json;
  } catch {
    return undefined;
  }
}

/** The slot's three holders in role order, as key ids (`<pair>#ed25519`, `<pair>#ml-dsa-65`). Undefined: not complete. */
function holdersOf(rows: readonly { key_id: string; holder_role: string }[]): SlotHolders | undefined {
  const order = HOLDER_ORDERS.find((o) => rows.every((r) => o.includes(r.holder_role)));
  if (!order) return undefined;
  const h = order.map((role) => rows.find((r) => r.holder_role === role));
  if (h.some((x) => !x)) return undefined;
  const ids = (h as { key_id: string }[]).map(
    (r): HolderKeyIds => ({ ed25519: r.key_id + ED_SUFFIX, mlDsa65: r.key_id + PQ_SUFFIX }),
  );
  return ids as unknown as SlotHolders;
}

/** The core gate's input for one deal, from one validated ledger. Throws `Error(<what is missing>)`. */
export async function buildReleaseInput(cfg: GateConfig, g: GateInput): Promise<ReleaseInput> {
  const { db } = cfg;
  const deal = await db.repos.deals.get(g.dealId);
  if (!deal?.shell_address || !deal.mint_tx_hash || !deal.nft_token_id) throw new Error('deal is not minted');
  if (!deal.lawyer_ops_a || !deal.lawyer_ops_b || !deal.escrow_owner || deal.escrow_sequence === null)
    throw new Error('deal has no ops accounts or escrow');
  if (!deal.condition_hex || !deal.releaser_account) throw new Error('deal has no condition or releaser');
  const ops = { LA: deal.lawyer_ops_a, LB: deal.lawyer_ops_b };

  const snap = await g.ledger.snapshot([deal.shell_address, ops.LA, ops.LB, cfg.verifierIssuer] as never);
  const wallet = snap.accounts[deal.shell_address];
  if (!wallet) throw new Error('deal wallet not on the ledger');
  const header = (h: { ledgerIndex: number; ledgerHash: string; closeTime: number }): LedgerHeader => ({
    index: h.ledgerIndex,
    hash: h.ledgerHash,
    closeTime: h.closeTime,
  });
  const head = header(snap.ledger as never);

  const mint = await g.ledger.tx(deal.mint_tx_hash as never);
  const mintTx: MintTx | undefined = mint
    ? {
        hash: mint.hash,
        validated: true,
        ledger_index: mint.ledgerIndex,
        tx_blob: encode(
          Object.fromEntries(Object.entries(mint.tx).filter(([k]) => !NOT_IN_LEDGER.includes(k))) as never,
        ),
        meta: mint.meta as MintTx['meta'],
      }
    : undefined;

  const [passports, zk, bars, keys, events] = await Promise.all([
    db.repos.passportAttestations.list(g.dealId),
    db.repos.zkProofs.list(g.dealId),
    db.repos.barDealLinks.list(g.dealId),
    db.repos.enrollmentKeys.listForDeal(g.dealId),
    db.repos.evidenceEvents.listAfter(g.dealId, -1, 100_000),
  ]);

  const barRecs: ReleaseInput['records']['bar'] = {};
  const named = new Set<number>();
  for (const l of bars) {
    const v = await db.repos.barVerifications.get(Buffer.from(l.verification_sha256).toString('hex'));
    const role = l.role === 'lawyerA' ? 'LA' : l.role === 'lawyerB' ? 'LB' : undefined;
    if (!v || !role) continue;
    barRecs[role] = { link: l.envelope, verification: v.envelope };
    named.add(v.checked_at_ledger);
  }
  for (const p of passports) named.add(p.anchor_ledger);
  const history: LedgerHeader[] = [];
  for (const n of named) if (n !== head.index) history.push(header((await g.ledger.ledgerHeader(n)) as never));

  const byKind = (kind: string) =>
    events.flatMap((e) => {
      const p = predicateOf(e.envelope);
      return p?.kind === kind ? [{ bytes: e.envelope, data: (p.data ?? {}) as Json }] : [];
    });
  const bySide = <T extends string>(kind: string, pick: (d: Json) => T | undefined) => {
    const out: Partial<Record<T, Uint8Array>> = {};
    for (const e of byKind(kind)) {
      const k = pick(e.data);
      if (k) out[k] = e.bytes;
    }
    return out;
  };
  const slotRows = (s: Slot) => keys.filter((k) => k.slot === s);
  const slotHolders = Object.fromEntries(SLOTS.map((s) => [s, holdersOf(slotRows(s))])) as Record<Slot, SlotHolders>;
  if (SLOTS.some((s) => !slotHolders[s])) throw new Error('a slot has no complete set of holder keys');
  const k = await cfg.verifierSigner.publicKeys();
  const servicePair = `service:${k.keyIds.ed25519}`;
  const keyRows: KeyRow[] = [
    ...keys.flatMap((r): KeyRow[] => [
      {
        keyId: r.key_id + ED_SUFFIX,
        alg: 'ed25519',
        publicKey: Uint8Array.from(Buffer.from(r.ed25519_pub, 'hex')),
        validFrom: r.valid_from,
        ...(r.valid_to === undefined || r.valid_to === null ? {} : { validTo: r.valid_to }),
        logged: true,
        pair: r.key_id,
      },
      {
        keyId: r.key_id + PQ_SUFFIX,
        alg: 'ml-dsa-65',
        publicKey: Uint8Array.from(Buffer.from(r.mldsa65_pub, 'base64')),
        validFrom: r.valid_from,
        ...(r.valid_to === undefined || r.valid_to === null ? {} : { validTo: r.valid_to }),
        logged: true,
        pair: r.key_id,
      },
    ]),
    { keyId: k.keyIds.ed25519, alg: 'ed25519', publicKey: k.ed25519, validFrom: 0, logged: true, pair: servicePair },
    { keyId: k.keyIds.mlDsa65, alg: 'ml-dsa-65', publicKey: k.mlDsa65, validFrom: 0, logged: true, pair: servicePair },
  ];

  const party = (side: 'A' | 'B') => {
    return side === 'A' ? g.publicData.payoutA : g.publicData.payoutB;
  };
  const objectsOf = (a: string) => snap.accounts[a]?.objects ?? [];
  return {
    profile: cfg.profile,
    ledger: {
      ...head,
      account: wallet.accountData as Json,
      objects: wallet.objects as Json[],
      ...(mintTx ? { mintTx } : {}),
      credentials: ROLES.flatMap((r) =>
        objectsOf(ops[r]).filter((o) => (o as Json).LedgerEntryType === 'Credential'),
      ) as Json[],
      opsAccounts: Object.fromEntries(
        ROLES.map((r) => [
          r,
          {
            validated: true,
            account_data: (snap.accounts[ops[r]]?.accountData ?? { Account: ops[r], Flags: 0 }) as Json,
          },
        ]),
      ) as ReleaseInput['ledger']['opsAccounts'],
      history,
    },
    records: {
      passport: Object.fromEntries(passports.map((p) => [p.side, p.envelope])),
      zkProof: Object.fromEntries(zk.map((z) => [z.side, z.proof])),
      onboarding: bySide('identity.onboarded', (d) => (d.side === 'A' || d.side === 'B' ? d.side : undefined)),
      bar: barRecs,
      opsBound: bySide('ops.bound', (d) => (d.role === 'LA' || d.role === 'LB' ? d.role : undefined)),
      pqBound: bySide('pq.bound', (d) => (SLOTS.includes(d.binding?.slot) ? (d.binding.slot as Slot) : undefined)),
      // OD-37: the logged envelopes; the gate verifies both and rebuilds shipMsg and rcptMsg itself.
      shipments: byKind('shipment.signed').map((e) => e.bytes),
      receipts: byKind('receipt.signed').map((e) => e.bytes),
      dkgCompleted: bySide('frost.dkg.completed', (d) => (SLOTS.includes(d.slot) ? (d.slot as Slot) : undefined)),
      keys: keyRows,
      slotHolders,
    },
    deal: {
      id: g.dealId,
      data: g.publicData,
      mintTxHash: deal.mint_tx_hash,
      nftokenId: deal.nft_token_id,
      credentialSubjects: [party('A'), party('B')],
      escrow: {
        owner: deal.escrow_owner,
        sequence: deal.escrow_sequence,
        amountDrops: deal.amount_drops,
        conditionHex: deal.condition_hex,
      },
    },
    submitter: deal.releaser_account,
    config: {
      verifierIssuer: cfg.verifierIssuer,
      verifierKeyIds: { ed25519: k.keyIds.ed25519, mlDsa65: k.keyIds.mlDsa65 },
    },
  };
}

/** The coordinator's `GatePort` over the real gate. Any failure to read the deal is a failed gate. */
export function realGate(cfg: GateConfig): GatePort {
  return {
    async run(g): Promise<GateResult> {
      let input: ReleaseInput;
      try {
        input = await buildReleaseInput(cfg, g);
      } catch (e) {
        return { ok: false, failed: [`INPUT_UNAVAILABLE:${(e as Error).message}`] };
      }
      const failed = checkRelease(input).filter((f) => !f.ok);
      return failed.length === 0 ? { ok: true } : { ok: false, failed: failed.map((f) => f.code) };
    },
  };
}

const b64 = (_k: string, v: unknown) => (v instanceof Uint8Array ? { $b64: Buffer.from(v).toString('base64') } : v);

/** `ledger.snapshot`: the gate's own input for a deal, as JSON (bytes are `{"$b64": ...}`), so a console re-runs the gate. */
export async function releaseInputJson(
  cfg: GateConfig,
  ledger: GateInput['ledger'],
  dealId: string,
): Promise<Record<string, unknown>> {
  const deal = await cfg.db.repos.deals.get(dealId);
  if (!deal) throw new Error('no such deal');
  const pd = await derivePublicData(cfg.db.repos, deal, (await loadConfig(cfg.db.repos, dealId)).identity_policy);
  if (pd.status !== 'complete') throw new Error(`the deal is not sealed yet: ${pd.missing.join(', ')}`);
  const input = await buildReleaseInput(cfg, { dealId, publicData: pd.publicData, claim: {} as never, ledger });
  return JSON.parse(JSON.stringify(input, b64)) as Record<string, unknown>;
}
