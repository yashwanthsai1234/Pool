// Checking the client's passport, method-aware (P4.4-03 to 05, 13, 14). The console makes the presence message, checks
// the proof (zero-knowledge, default) or the chip (fallback), waits for the client's presence signature (a FROST
// signature by the client's slot key), and only then signs the attestation. Afterwards it drops the DG1 and SOD bytes
// and any proof payload (P4.4-05). Nothing here is written to IndexedDB, so nothing can be left there.
// The method is the sealed idMethod of the client's side; a deal whose seal forbids it cannot be sealed at all (dealSeal),
// and a stored attestation of another method is the gate's IDENTITY_POLICY_OK finding.
// Source: DESIGN 6.15 (presence, attestation), 6.10 (zero-knowledge), 6.17; OD-22, OD-23, OD-29
import { type ChipData, createSession, receiveChip, type Sealed, type Session } from '@legx/chip-link';
import { checkFreshNonce, type Method, presenceMsg, verifyAttestation } from '@legx/core/attest';
import { bytesToHex, dealSeal, hexToBytes, randomBytes, sha256 } from '@legx/core/dealcore';
import { verifyEd25519Strict } from '@legx/core/frost';
import { chipChecks } from '@legx/core/passport/passiveAuth';
import { toBase64 } from '@legx/core/pq';
import { checkZkResult, releaseBoundValue, trustRecordOf, zkIdentityCommitment } from '@legx/core/zkIdentity';
import { signSelfChecked } from './attestation.ts';
import { createEventAppender } from './events.ts';
import { createListeners } from './listeners.ts';
import { type ConsoleDeps, ConsoleError, SIDE_OF } from './ports.ts';

type ItemStatus = 'pass' | 'fail' | 'pending';
export interface CheckItem {
  name: string;
  status: ItemStatus;
  /** Why it failed (or "not reached" after an earlier failure). */
  reason?: string;
}
export interface PassportState {
  phase: 'idle' | 'awaiting-check' | 'checked' | 'signed';
  method?: Method;
  items: CheckItem[];
  presence: 'none' | 'valid' | 'invalid';
  /** The message the client's phone signs, hex, once `begin` ran. */
  presenceMsgHex?: string;
  /** Chip method over the reader: the QR code to show. */
  qr?: string;
  canSign: boolean;
  /** Why signing is off, in words. */
  blocked?: string;
}

export type ChipSource = { kind: 'fixture'; data: ChipData } | { kind: 'reader'; sealed: Sealed };

const ZK_ITEMS = [
  'proof_verified',
  'identifier_matches',
  'bound_value_is_presence_msg',
  'document_not_expired',
  'face_match_passed',
];
const CHIP_ITEMS = [
  'sod_signature_valid',
  'ds_cert_chains_to_csca',
  'dg1_hash_in_sod',
  'document_not_expired',
  'commitment_opens',
  'chip_authentication',
];

// Which chip check a core failure code belongs to (chipChecks stops at the first failure).
function chipItemOf(code: string): string {
  if (/^(SOD_|DS_CERT_MISSING|LDS_)/.test(code) || code === 'SOD_SIGNATURE_INVALID') return 'sod_signature_valid';
  if (/^(DS_|CSCA_)/.test(code)) return 'ds_cert_chains_to_csca';
  if (/^(DG\d+_HASH|DG1_MALFORMED|MRZ_CHECK)/.test(code)) return 'dg1_hash_in_sod';
  if (code === 'DOCUMENT_EXPIRED') return 'document_not_expired';
  if (code === 'COMMITMENT_MISMATCH') return 'commitment_opens';
  return 'chip_authentication';
}

type Draft = {
  anchor: { ledger_index: number; ledger_hash: string };
  nonce: Uint8Array;
  msg: Uint8Array;
  checks?: Record<string, unknown>;
  proofSet?: Uint8Array;
  session?: Session;
  chip?: ChipData;
  presenceSig?: Uint8Array;
};

export function createPassportFlow(deps: ConsoleDeps) {
  const { deal, role } = deps;
  const side = SIDE_OF[role];
  const data = deal.data;
  const method: Method = side === 'A' ? data.idMethodA : data.idMethodB;
  const commitment = side === 'A' ? data.commitmentA : data.commitmentB;
  const used = new Set<string>();
  const append = createEventAppender(deps);
  const { notify, subscribe } = createListeners();
  let draft: Draft | undefined;
  let state: PassportState = { phase: 'idle', items: [], presence: 'none', canSign: false };

  const set = (patch: Partial<PassportState>) => {
    const next = { ...state, ...patch };
    const allPass = next.items.length > 0 && next.items.every((i) => i.status === 'pass');
    const blocked =
      next.phase === 'signed'
        ? undefined
        : !allPass
          ? 'The passport check has not passed.'
          : next.presence !== 'valid'
            ? "Waiting for your client's presence signature."
            : undefined;
    state = { ...next, canSign: next.phase === 'checked' && blocked === undefined, ...(blocked ? { blocked } : {}) };
    if (blocked === undefined) delete state.blocked;
    notify();
  };

  const zkItems = async (): Promise<{ items: CheckItem[]; checks?: Record<string, unknown> }> => {
    const d = draft as Draft;
    const { request, proofSet } = deps.identity.zkRequest(d.msg);
    const result = await deps.identity.zkVerify(request);
    const salt = await deps.identity.salt();
    const bound = releaseBoundValue(d.msg);
    const verdict = checkZkResult(result, request.originalQuery, {
      stage: 'release',
      dealId: deal.id,
      boundValue: bound,
      profile: deal.profile,
      identity: { zkSalt32: salt, commitment },
    });
    const errs = Object.entries(result.queryResultErrors);
    const facematchMode = (request.originalQuery.facematch as { mode?: string } | undefined)?.mode;
    const proofHash = bytesToHex(sha256(proofSet)) === result.proofSha256;
    const ok: Record<string, boolean> = {
      proof_verified: result.verified && errs.length === 0 && proofHash,
      identifier_matches:
        result.uniqueIdentifier !== null &&
        bytesToHex(zkIdentityCommitment(salt, result.uniqueIdentifier)) === commitment,
      bound_value_is_presence_msg: result.committedInputs.custom_data === bound,
      document_not_expired: !errs.some(([c, k]) => c === 'expiry_date' || 'date' in k),
      face_match_passed: !errs.some(([c]) => c === 'facematch') && facematchMode === 'strict',
    };
    const why: Record<string, string> = {
      proof_verified: proofHash ? 'the proof does not verify' : 'the stored proof set does not match its hash',
      identifier_matches: 'the identifier does not open the sealed commitment',
      bound_value_is_presence_msg: 'the proof is not bound to this presence message',
      document_not_expired: 'the document is expired',
      face_match_passed: 'face match',
    };
    const items: CheckItem[] = ZK_ITEMS.map((name) => ({
      name,
      status: ok[name] ? 'pass' : 'fail',
      ...(ok[name] ? {} : { reason: why[name] as string }),
    }));
    if (!verdict.ok && items.every((i) => i.status === 'pass'))
      items.push({ name: 'trust_and_scope', status: 'fail', reason: verdict.code });
    if (!verdict.ok) return { items };
    d.proofSet = proofSet;
    return {
      items,
      checks: { ...ok, proof_sha256: result.proofSha256, trust: trustRecordOf(result) },
    };
  };

  const chipItems = async (src: ChipSource): Promise<{ items: CheckItem[]; checks?: Record<string, unknown> }> => {
    const d = draft as Draft;
    const ctx = {
      trustList: deps.identity.trustList,
      atTime: deps.now(),
      salt: await deps.identity.salt(),
      commitment: hexToBytes(commitment),
      presenceMsg: d.msg,
    };
    let result: Awaited<ReturnType<typeof chipChecks>>;
    if (src.kind === 'fixture') {
      d.chip = src.data;
      result = await chipChecks({ ...src.data, ...ctx });
    } else {
      if (!d.session) throw new ConsoleError('NO_SESSION');
      result = (await receiveChip(d.session, src.sealed, ctx)) as typeof result;
    }
    if (result.ok) {
      d.checks = result.checks as unknown as Record<string, unknown>;
      return { items: CHIP_ITEMS.map((name) => ({ name, status: 'pass' as const })), checks: d.checks };
    }
    const at = CHIP_ITEMS.indexOf(chipItemOf(result.code));
    return {
      items: CHIP_ITEMS.map((name, i) => ({
        name,
        status: i < at ? 'pass' : i === at ? 'fail' : 'pending',
        ...(i === at ? { reason: result.code } : i > at ? { reason: 'not reached' } : {}),
      })),
    };
  };

  /** Drops chip bytes and proof payloads (P4.4-05): zeroed, then forgotten. */
  const drop = () => {
    const d = draft;
    if (d?.chip) for (const b of [d.chip.dg1, d.chip.sod, d.chip.dg14, d.chip.dg15, d.chip.aaSignature]) b?.fill(0);
    d?.proofSet?.fill(0);
    d?.nonce.fill(0);
    draft = undefined;
  };

  return {
    state: () => state,
    subscribe,
    method,

    /** Anchors on the console's own public connection, makes a fresh nonce and the presence message. */
    async begin(): Promise<PassportState> {
      drop();
      const header = await deps.publicLedger.latest();
      const nonce = (deps.nonce ?? (() => randomBytes(32)))();
      const fresh = checkFreshNonce(nonce, used);
      if (!fresh.ok) throw new ConsoleError(fresh.code);
      used.add(bytesToHex(nonce));
      const msg = presenceMsg(dealSeal(data), side, hexToBytes(header.hash), nonce);
      draft = { anchor: { ledger_index: header.index, ledger_hash: header.hash }, nonce, msg };
      if (method === 'nfc-chip') draft.session = await createSession(msg);
      set({
        phase: 'awaiting-check',
        method,
        items: [],
        presence: 'none',
        presenceMsgHex: bytesToHex(msg),
        ...(draft.session ? { qr: draft.session.qr } : {}),
      });
      return state;
    },

    /** The method-aware check. A method that the policy forbids fails before anything else runs. */
    async check(chip?: ChipSource): Promise<PassportState> {
      if (!draft) throw new ConsoleError('NOT_STARTED');
      const r =
        method === 'zkpassport'
          ? await zkItems()
          : await chipItems(
              chip ??
                (() => {
                  throw new ConsoleError('NO_CHIP_DATA');
                })(),
            );
      if (r.checks) draft.checks = r.checks;
      else delete draft.checks;
      set({ phase: 'checked', items: r.items });
      return state;
    },

    /** The client's presence signature: a plain Ed25519 signature by the sealed client slot key over presenceMsg. */
    submitPresence(sig: Uint8Array): PassportState {
      if (!draft) throw new ConsoleError('NOT_STARTED');
      const pub = hexToBytes(side === 'A' ? data.xPubA : data.xPubB);
      const ok = sig.length === 64 && verifyEd25519Strict(sig, draft.msg, pub);
      if (ok) draft.presenceSig = sig;
      else delete draft.presenceSig;
      set({ presence: ok ? 'valid' : 'invalid' });
      return state;
    },

    /** Signs the attestation (hybrid, by this lawyer's enrollment keys), self-checks it, records it, drops the data. */
    async sign(): Promise<Uint8Array> {
      if (!state.canSign || !draft?.checks || !draft.presenceSig) throw new ConsoleError('NOT_READY', state.blocked);
      const d = draft;
      const payload = {
        deal_id: deal.id,
        contract_root: data.contractRoot,
        deal_seal: bytesToHex(dealSeal(data)),
        side,
        commitment,
        ledger_anchor: d.anchor,
        method,
        checks: d.checks,
        presence_sig: bytesToHex(d.presenceSig as Uint8Array),
        lawyer_nonce: bytesToHex(d.nonce),
        checked_by_role: role === 'LA' ? 'lawyerA' : 'lawyerB',
        sig_algs: ['ed25519', 'ml-dsa-65'],
      };
      const bytes = await signSelfChecked(deps.signer, payload, (envelope) =>
        verifyAttestation({
          envelope,
          side,
          deal: { id: deal.id, data },
          sealedKeys: { lawyerKeyIds: deps.lawyerKeyIds, registry: deps.registry },
          now: deps.now(),
          profile: deal.profile,
          ledgerLookup: deps.ledgerLookup,
          zkProof: d.proofSet,
        }),
      );
      if (d.proofSet) await deps.evidence.attach('zk-proof', side, d.proofSet);
      await append('passport.verified', { side, attestation: toBase64(bytes) });
      drop();
      set({ phase: 'signed', items: state.items });
      delete state.qr;
      delete state.presenceMsgHex;
      return bytes;
    },
  };
}
