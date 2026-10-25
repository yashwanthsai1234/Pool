// The real `PartyServices` (I-31): the signed API client, the vault frame, the coordinator's validated-ledger relay,
// the phone's own check of every stored envelope against the pinned hybrid registry, and the presence submission.
// Nothing here is a stub: a service that cannot be provided is left out of the object, and its screen says so.
// Source: DESIGN.md 6.3 (pinned hybrid keys), 6.15 (presence), 8.10 (client records); build/DECISIONS.md OD-5, OD-10
import type { EnrollmentKey } from '@legx/contracts/records';
import { hexToBytes } from '@legx/core/dealcore';
import { type Envelope, entryLink } from '@legx/core/evidence';
import { type KeyRegistry, verifyHybrid } from '@legx/core/hybridEnvelope';
import { fromBase64Strict } from '@legx/core/pq';
import type { connectVault } from '@legx/vault';
import type { ApiClient } from '../../lib/api.ts';
import { loadSealedDealFromApi, type SealVault } from '../../lib/seal.ts';
import type { PartyServices } from './-context.tsx';

type FrameVault = ReturnType<typeof connectVault>;

export interface PartyServiceDeps {
  dealId: string;
  role: PartyServices['role'];
  api: ApiClient;
  vault: Pick<FrameVault, 'signFrost' | 'signMultisig' | 'shellKey' | 'signShell' | 'signSingle'> & SealVault;
  /** The validated ledger index from the phone's own node (OD-10): `LastLedgerSequence` of a transaction it builds. */
  validatedIndex: () => Promise<number>;
  /** Ripple-epoch seconds of the newest validated ledger the phone has seen (the time a record is checked at). */
  closeTime: () => number;
  /** The validated ledger index of a transaction, asked of the phone's own public XRPL node (OD-10). */
  txLedgerIndex: (txHash: string) => Promise<number | undefined>;
}

const half = (keyid: string) => {
  const [pair, alg] = keyid.split('#');
  return pair && (alg === 'ed25519' || alg === 'ml-dsa-65') ? ({ pair, alg } as const) : undefined;
};

/** One enrollment key row as the verifier needs it (`<pair>#ed25519` and `<pair>#ml-dsa-65` are the two halves). */
function registered(row: EnrollmentKey, alg: 'ed25519' | 'ml-dsa-65') {
  return {
    alg,
    publicKey:
      alg === 'ed25519' ? hexToBytes(row.ed25519_pub) : (fromBase64Strict(row.mldsa65_pub) ?? new Uint8Array()),
    validFrom: row.valid_from,
    ...(row.valid_to === undefined ? {} : { validTo: row.valid_to }),
    // The coordinator's key registry is the pinned directory (6.3). Log inclusion of the key hash is checked at the
    // lawyer and at checkpoint time, not on the phone (known gap, status file).
    logged: true,
    pair: row.key_id,
  } as const;
}

export function createPartyServices(d: PartyServiceDeps): PartyServices {
  const side = d.role === 'alice' ? 'A' : 'B';
  const rows = new Map<string, EnrollmentKey>();
  const txIndex = new Map<string, number | undefined>();
  let nonce: string | undefined;
  // OD-36: the frame signs only for a deal whose recomputed seal equals its pin; pinned and loaded once, before the first signature.
  let sealed: Promise<void> | undefined;
  const sealedFirst =
    <A extends unknown[], R>(f: (...a: A) => Promise<R>) =>
    async (...a: A) => {
      sealed ??= loadSealedDealFromApi(d.vault, d.api, d.dealId).catch((e) => {
        sealed = undefined;
        throw e;
      });
      await sealed;
      return f(...a);
    };

  const registry: KeyRegistry = (keyid) => {
    const h = half(keyid);
    const row = h && rows.get(h.pair);
    return h && row ? registered(row, h.alg) : undefined;
  };

  const vault = {
    ...d.vault,
    signFrost: sealedFirst(d.vault.signFrost),
    signMultisig: sealedFirst(d.vault.signMultisig),
    signSingle: sealedFirst(d.vault.signSingle),
    signShell: sealedFirst(d.vault.signShell),
  };

  return {
    dealId: d.dealId,
    role: d.role,
    api: d.api,
    vault: { signFrost: vault.signFrost, signMultisig: vault.signMultisig },
    // Alice only: the shell key is made in the frame; the page learns the address, never the key.
    ...(d.role === 'alice'
      ? {
          runLockSetup: async (onStep: Parameters<NonNullable<PartyServices['runLockSetup']>>[0]) => {
            const { runLockSequence } = await import('./-lock.ts');
            await runLockSequence({
              api: d.api,
              vault,
              dealId: d.dealId,
              validatedIndex: d.validatedIndex,
              onStep,
            });
          },
        }
      : {}),
    ...(d.role === 'alice' ? { createShellKey: async () => (await d.vault.shellKey(d.dealId)).address } : {}),
    acceptBadge: async () => {
      const { acceptBadgeTx } = await import('./-badge.ts');
      await acceptBadgeTx({
        api: d.api,
        vault,
        dealId: d.dealId,
        role: d.role,
        validatedIndex: d.validatedIndex,
      });
    },
    accountInfo: async (address) => {
      const r = await d.api.ledger.accountInfo({ address });
      return r.exists ? { flags: r.flags } : undefined;
    },
    checkEnvelope: (env: Envelope) => verifyHybrid(env, registry, d.closeTime()).ok,
    ledgerIndexOf: (txHash) => txIndex.get(txHash),
    prepareEnvelopes: async (entries) => {
      const keyIds = new Set<string>();
      const hashes = new Set<string>();
      for (const e of entries) {
        const link = entryLink(e);
        for (const s of link?.env.signatures ?? []) {
          const h = half(s.keyid);
          if (h) keyIds.add(h.pair);
        }
        const tx = (link?.predicate.ledger as { tx_hash?: unknown } | undefined)?.tx_hash;
        if (typeof tx === 'string') hashes.add(tx);
      }
      await Promise.all([
        ...[...keyIds]
          .filter((k) => !rows.has(k))
          .map(async (keyId) => {
            rows.set(keyId, await d.api.keys.get({ keyId: keyId as never }));
          }),
        ...[...hashes]
          .filter((h) => !txIndex.has(h))
          .map(async (h) => {
            txIndex.set(h, await d.txLedgerIndex(h));
          }),
      ]);
    },
    presenceRequest: async () => {
      const s = await d.api.presence.get({ dealId: d.dealId, side });
      if (!s.request) throw new Error('NO_PRESENCE_REQUEST');
      nonce = s.request.lawyerNonce;
      return s.request;
    },
    submitPresence: async ({ signature }) => {
      if (!nonce) throw new Error('NO_PRESENCE_REQUEST');
      await d.api.presence.submit({
        dealId: d.dealId,
        side,
        lawyerNonce: nonce as never,
        signature: signature as never,
      });
    },
  };
}
