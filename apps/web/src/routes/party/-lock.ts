// Steps 5a to 5g of the lock (DESIGN 5.2, IMPLEMENTATION "5a to 5g"): Alice's phone signs the shell's setup transactions with the
// shell setup key inside the vault frame, in order, one validated ledger at a time, and the last one (DisableMaster) retires the key.
// The frame refuses anything that is not a setup transaction of the shell's own account; this page only sequences them from
// the deal it recomputed the seal of. Source: https://xrpl.org/docs/references/protocol/transactions/types (SignerListSet,
// AccountSet, DepositPreauth, CredentialCreate)
import { bytesToHex, sha256 } from '@legx/core/dealcore';
import type { ApiClient } from '../../lib/api.ts';
import { fetchSealedDeal } from '../../lib/seal.ts';

const VALID_FOR_LEDGERS = 20;
const FEE_DROPS = '10';
const utf8Hex = (s: string) => bytesToHex(new TextEncoder().encode(s)).toUpperCase();

export type LockStep = { id: string; status: 'running' | 'done' | 'failed'; detail?: string };

export async function runLockSequence(d: {
  api: ApiClient;
  vault: {
    signShell(dealId: string, tx: Record<string, unknown>): Promise<string>;
    shellKey(dealId: string): Promise<{ address: string }>;
  };
  dealId: string;
  validatedIndex: () => Promise<number>;
  onStep?: (s: LockStep) => void;
}): Promise<void> {
  const sealed = await fetchSealedDeal(d.api, d.dealId);
  if (sealed.state === 'incomplete') throw new Error('DEAL_NOT_SEALED');
  if (sealed.state === 'seal-mismatch') throw new Error('SEAL_MISMATCH');
  const p = sealed.publicData;
  const shell = (await d.vault.shellKey(d.dealId)).address;
  if (shell !== p.walletAddress) throw new Error('NOT_MY_SHELL'); // the sealed wallet is not the one this device made
  const { deriveAddress } = await import('xrpl');
  const sigs = await bindingSigs(d.api, d.dealId);
  const type = (side: 'A' | 'B') => utf8Hex(`LEGX_PARTY_${side}`);
  const uri = (side: 'A' | 'B') =>
    utf8Hex(`legx:bind:v1:${bytesToHex(sha256(sigs[side] ?? new Uint8Array())).toUpperCase()}`);
  const accountSet = (SetFlag: number, extra: Record<string, unknown> = {}) => ({
    TransactionType: 'AccountSet',
    SetFlag,
    ...extra,
  });
  const steps: [string, Record<string, unknown>][] = [
    [
      '5a SignerListSet',
      {
        TransactionType: 'SignerListSet',
        SignerQuorum: p.quorum,
        SignerEntries: p.signerAccounts.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
      },
    ],
    ['5b AccountSet Domain and DepositAuth', accountSet(9, { Domain: sealed.domain.toUpperCase() })],
    ...[12, 13, 14, 15].map((f): [string, Record<string, unknown>] => [`5c AccountSet flag ${f}`, accountSet(f)]),
    ['5d DepositPreauth', { TransactionType: 'DepositPreauth', Authorize: p.releaserAccount }],
    ...(['A', 'B'] as const).map((side): [string, Record<string, unknown>] => [
      `5e CredentialCreate ${side}`,
      {
        TransactionType: 'CredentialCreate',
        Subject: deriveAddress(side === 'A' ? p.xPubA : p.xPubB),
        CredentialType: type(side),
        URI: uri(side),
      },
    ]),
    ['5g AccountSet DisableMaster', accountSet(4)],
  ];
  for (const [id, body] of steps) {
    d.onStep?.({ id, status: 'running' });
    try {
      const [info, index] = await Promise.all([d.api.ledger.accountInfo({ address: shell }), d.validatedIndex()]);
      if (!info.exists) throw new Error('SHELL_NOT_FUNDED');
      const blob = await d.vault.signShell(d.dealId, {
        ...body,
        Account: shell,
        Fee: FEE_DROPS,
        Sequence: info.sequence,
        LastLedgerSequence: index + VALID_FOR_LEDGERS,
      });
      const res = await d.api.ledger.submit({ txBlob: blob });
      if (res.status !== 'validated' || !res.result.startsWith('tes'))
        throw new Error(`LEDGER_REFUSED ${res.status === 'expired' ? 'expired' : res.result}`);
      d.onStep?.({ id, status: 'done' });
    } catch (e) {
      d.onStep?.({ id, status: 'failed', detail: e instanceof Error ? e.message : String(e) });
      throw e;
    }
  }
}

/** The 64-byte binding signatures of the two client slots, read from the stored `key.bound` events. */
async function bindingSigs(api: ApiClient, dealId: string): Promise<Partial<Record<'A' | 'B', Uint8Array>>> {
  const out: Partial<Record<'A' | 'B', Uint8Array>> = {};
  const { events } = await api.events.list({ dealId, afterSeq: -1, limit: 500 });
  for (const e of events) {
    try {
      const env = JSON.parse(atob(e.envelope)) as { payload: string };
      const st = JSON.parse(atob(env.payload)) as {
        predicate?: { kind?: string; data?: { slot?: string; binding_sig?: string } };
      };
      const data = st.predicate?.data;
      if (
        st.predicate?.kind === 'key.bound' &&
        (data?.slot === 'A' || data?.slot === 'B') &&
        data.binding_sig?.length === 128
      )
        out[data.slot] = Uint8Array.from(data.binding_sig.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
    } catch {
      // an event this reader cannot parse is not a binding
    }
  }
  if (!out.A || !out.B) throw new Error('BINDINGS_MISSING');
  return out;
}
