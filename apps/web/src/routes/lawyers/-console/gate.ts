// The release gate screen (P4.4-06 to 08, 10, 13, 15). The gate runs here, in the browser, on a snapshot the coordinator
// relays. A hacked coordinator could feed a false snapshot, so the console checks the snapshot's ledger hash against its
// own read-only public XRPL connection first (OD-10); if they disagree it refuses. The relay never supplies the deal
// data or the submitter: the console uses its own copies.
// Source: DESIGN 6.17, D22, D23; IMPLEMENTATION 4.4 "Think hard"
import type { Finding } from '@legx/contracts/records';
import { bytesToHex } from '@legx/core/dealcore';
import { fromBase64Strict } from '@legx/core/pq';
import { buildGatePassedRecord, checkRelease, gateMemo, type ReleaseInput } from '@legx/core/releaseGate';
import { signWithApproval } from './approval.ts';
import type { DealActions } from './deal.ts';
import { createListeners } from './listeners.ts';
import { type ConsoleDeps, ConsoleError, type Side } from './ports.ts';

/** The snapshot may trail the validated ledger by at most this many ledgers (about 20 seconds). */
export const SNAPSHOT_MAX_LAG = 5;

export interface GateState {
  status: 'idle' | 'running' | 'done' | 'refused';
  refusal?: { code: 'LEDGER_MISMATCH' | 'PUBLIC_LEDGER_UNAVAILABLE' | 'RELAY_FAILED'; reason: string };
  ledger?: { index: number; hash: string };
  findings: Finding[];
  /** Identity method of each side's stored attestation, as signed in it. */
  methods: Record<Side, { method: string; label: string }>;
  canRelease: boolean;
  /** Why the release button is off. */
  reason?: string;
}

const LABEL: Record<string, string> = { zkpassport: 'Zero-knowledge', 'nfc-chip': 'Chip' };
const NONE = { method: 'none', label: 'No attestation' };

function methodOf(envelope: Uint8Array | undefined): { method: string; label: string } {
  try {
    const env = JSON.parse(new TextDecoder().decode(envelope)) as { payload: string };
    const body = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload))) as { method?: string };
    return body.method ? { method: body.method, label: LABEL[body.method] ?? body.method } : NONE;
  } catch {
    return NONE;
  }
}

export function createGate(deps: ConsoleDeps, actions: DealActions) {
  const { deal } = deps;
  let input: ReleaseInput | undefined;
  const { notify, subscribe } = createListeners();
  let state: GateState = { status: 'idle', findings: [], methods: { A: NONE, B: NONE }, canRelease: false };
  const set = (s: GateState) => {
    state = s;
    notify();
  };

  /** Decides whether the button is on, from the findings, the role, the code and how current the snapshot is. */
  async function decide(): Promise<Pick<GateState, 'canRelease' | 'reason'>> {
    const bad = state.findings.find((f) => !f.ok);
    if (bad) return { canRelease: false, reason: `${bad.code} fails${bad.detail ? `: ${bad.detail}` : ''}` };
    if (deps.role !== 'LB') return { canRelease: false, reason: 'Only lawyer B releases the money.' };
    if (!actions.hasReleaseCode()) return { canRelease: false, reason: 'Make the release code first.' };
    const latest = await deps.publicLedger.latest().catch(() => undefined);
    if (!latest || !state.ledger) return { canRelease: false, reason: 'The public ledger is not reachable.' };
    if (latest.index - state.ledger.index > SNAPSHOT_MAX_LAG)
      return {
        canRelease: false,
        reason: 'The snapshot is older than the current validated ledger. Run the gate again.',
      };
    return { canRelease: true };
  }

  async function refuse(code: NonNullable<GateState['refusal']>['code'], reason: string) {
    input = undefined;
    set({
      status: 'refused',
      refusal: { code, reason },
      findings: [],
      methods: { A: NONE, B: NONE },
      canRelease: false,
      reason,
    });
  }

  return {
    state: () => state,
    subscribe,

    /** Reads one validated snapshot, checks it against the public node, runs `checkRelease` locally. */
    async run(): Promise<GateState> {
      set({ ...state, status: 'running', canRelease: false });
      let snap: ReleaseInput;
      try {
        snap = await deps.ledger.snapshot(deal.id);
      } catch (e) {
        await refuse('RELAY_FAILED', `The ledger relay failed: ${e instanceof Error ? e.message : String(e)}`);
        return state;
      }
      const theirs = await deps.publicLedger.hashAt(snap.ledger.index).catch(() => undefined);
      if (theirs === undefined) {
        await refuse(
          'PUBLIC_LEDGER_UNAVAILABLE',
          'The public XRPL node could not confirm this ledger, so the gate does not run.',
        );
        return state;
      }
      if (theirs.toUpperCase() !== snap.ledger.hash.toUpperCase()) {
        await refuse(
          'LEDGER_MISMATCH',
          'The coordinator and the public XRPL node disagree about this ledger. Refusing.',
        );
        return state;
      }
      input = {
        ...snap,
        profile: deal.profile,
        submitter: deps.ops.address,
        deal: { ...snap.deal, id: deal.id, data: deal.data },
      };
      const findings = checkRelease(input);
      const methods = { A: methodOf(input.records.passport.A), B: methodOf(input.records.passport.B) };
      set({
        status: 'done',
        ledger: { index: input.ledger.index, hash: input.ledger.hash },
        findings,
        methods,
        canRelease: false,
      });
      set({ ...state, ...(await decide()) });
      return state;
    },

    /** Re-evaluates the button, for example on each new validated ledger. */
    async refresh(): Promise<GateState> {
      if (state.status === 'done') set({ ...state, ...(await decide()) });
      return state;
    },

    /** P4.4-08: gate record, then the EscrowFinish with the gate memo, then `release.performed`. */
    async release() {
      await this.refresh();
      if (!state.canRelease || !input) throw new ConsoleError('RELEASE_OFF', state.reason);
      const gate = input;
      if (actions.condition() !== gate.deal.escrow.conditionHex.toUpperCase())
        throw new ConsoleError('CODE_MISMATCH', 'the release code does not open the escrow condition');
      const record = await buildGatePassedRecord(
        gate,
        await deps.evidence.fields(new Uint8Array()),
        deps.signer,
        (envelope) => signWithApproval(deps, { kind: 'gate-record', envelope }),
      );
      await deps.evidence.append(record.envelopeBytes);
      const done = await actions.submitSingle({
        TransactionType: 'EscrowFinish',
        Owner: gate.deal.escrow.owner,
        OfferSequence: gate.deal.escrow.sequence,
        Condition: gate.deal.escrow.conditionHex,
        Fulfillment: actions.fulfillment(),
        Memos: [{ Memo: gateMemo(record.leafHash) }],
        Fee: actions.finishFee(),
      });
      if (!done.validated || done.result !== 'tesSUCCESS') throw new ConsoleError('FINISH_FAILED', done.result);
      await actions.appendEvent('release.performed', {
        finish_tx_hash: done.hash,
        ledger_index: done.ledgerIndex,
        gate_leaf_hash: bytesToHex(record.leafHash),
      });
      return done;
    },
  };
}
