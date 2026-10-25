// A full deal driven through the public API, step by step, so each test can stop at the state it needs.

import { GATE_CODES } from '@legx/contracts/records';
import { lsf } from '@legx/core/lockcheck';
import { toBase64 } from '@legx/core/pq';
import { deriveAddress } from 'xrpl';
import {
  addTx,
  call,
  contractRoot,
  hex,
  holderOf,
  PAY_A,
  PAY_B,
  post,
  type Role,
  rndHex,
  SLOT,
  type World,
} from './world.ts';

export const CONDITION = `A0258020${'CC'.repeat(32)}810120`;
export const AMOUNT = '5000000000';
/** The quarantine escrow's OfferSequence (the EscrowCreate's Sequence). */
const ESCROW_SEQUENCE = 7;
/** An EscrowFinish or EscrowCancel names the escrow by Owner and OfferSequence. */
export const ourEscrow = (w: World) => ({ Owner: account(w, 'alice'), OfferSequence: ESCROW_SEQUENCE });

const pub = (w: World, role: Role) => w.parties[role].wallet.publicKey;
export const account = (w: World, role: Role) => deriveAddress(pub(w, role));
const b64json = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64');

export const ok = (r: { status: number; body: unknown }) => {
  if (r.status !== 200) throw new Error(`HTTP ${r.status} ${JSON.stringify(r.body)}`);
  return r.body as Record<string, any>;
};

export async function keyBound(w: World, id: string, role: Role) {
  return post(w, id, role, 'key.bound', {
    slot: SLOT[role],
    xrpl_pubkey: pub(w, role),
    commitment: rndHex(32),
    binding_sig: rndHex(64),
  });
}

export async function dkgDone(w: World, id: string, role: Role) {
  const p = w.parties[role];
  return post(w, id, role, 'frost.dkg.completed', {
    session_id: rndHex(32),
    slot: p.slot,
    group_pub: pub(w, role),
    slot_policy: rndHex(32),
    roles: p.holders.map((h) => h.holderRole),
    transcript_hash: rndHex(32),
    holder_sigs: p.holders.map((h) => ({ key_id: h.pairId, sig: rndHex(64) })),
    verifying_shares: p.holders.map(() => ({ identifier: rndHex(32), share: rndHex(32) })),
    test_sigs: [rndHex(64), rndHex(64), rndHex(64)],
  });
}

export async function lawyerSigned(w: World, id: string, role: 'lawyerA' | 'lawyerB') {
  return post(w, id, role, 'contract.lawyer_signed', {
    role: SLOT[role],
    contract_root: contractRoot,
    wallet_address: w.addr.shell,
    lawyer_pub: pub(w, role),
    contract_sig: rndHex(64),
  });
}

export async function opsBound(w: World, id: string, role: 'lawyerA' | 'lawyerB') {
  return post(w, id, role, 'ops.bound', {
    role: SLOT[role],
    ops_account: role === 'lawyerA' ? w.addr.opsA : w.addr.opsB,
    ops_pub: pub(w, role),
    lawyer_pub: pub(w, role),
    bar_commitment: rndHex(32),
    sig_ops: rndHex(64),
    sig_lawyer: rndHex(64),
  });
}

export async function identityOnboarded(w: World, id: string, side: 'A' | 'B') {
  return post(w, id, side === 'A' ? 'lawyerA' : 'lawyerB', 'identity.onboarded', {
    side,
    attestation: b64json({ payload: b64json({ method: side === 'A' ? 'zkpassport' : 'nfc-chip' }) }),
  });
}

/** Contract fixed, public data of every role logged: the deal is ready for the seal. */
export async function joinAll(w: World, id: string) {
  ok(await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/wallet`, { dealId: id, walletAddress: w.addr.shell }));
  ok(await call(w, holderOf(w, 'lawyerA'), 'POST', `/deals/${id}/contract`, { dealId: id, contractRoot }));
  for (const r of ['alice', 'lawyerA', 'bob', 'lawyerB'] as Role[]) {
    ok(await keyBound(w, id, r));
    ok(await dkgDone(w, id, r));
  }
  ok(await lawyerSigned(w, id, 'lawyerA'));
  ok(await lawyerSigned(w, id, 'lawyerB'));
  ok(await opsBound(w, id, 'lawyerA'));
  ok(await opsBound(w, id, 'lawyerB'));
  ok(await identityOnboarded(w, id, 'A'));
  ok(await identityOnboarded(w, id, 'B'));
  ok(
    await post(w, id, 'lawyerA', 'nft.minted', {
      nftoken_id: rndHex(32).toUpperCase(),
      mint_tx_hash: addTx(w, 'NFTokenMint', w.addr.opsA),
      minter: w.addr.opsA,
      signed_contract_seal: rndHex(32),
    }),
  );
}

async function toQuarantined(w: World, id: string) {
  await joinAll(w, id);
  ok(
    await post(w, id, 'alice', 'shell.opened', {
      wallet_address: w.addr.shell,
      funding_tx_hash: addTx(w, 'Payment', account(w, 'alice')),
    }),
  );
  const cancelAfter = w.ledger.closeTime + 200_000;
  ok(
    await post(w, id, 'alice', 'escrow.created', {
      escrow: {
        owner: account(w, 'alice'),
        offer_sequence: ESCROW_SEQUENCE,
        amount_drops: AMOUNT,
        condition: CONDITION,
        cancel_after: cancelAfter,
      },
      tx_hash: addTx(w, 'EscrowCreate', account(w, 'alice'), {
        Destination: w.addr.shell,
        Amount: AMOUNT,
        Condition: CONDITION,
        CancelAfter: cancelAfter,
        Sequence: ESCROW_SEQUENCE,
      }),
    }),
  );
}

export async function publicData(w: World, id: string) {
  return ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}/public-data`));
}

/** The post-quantum binding of every slot over the coordinator's seal; the fourth one makes the keys ready. */
export async function pqBind(w: World, id: string) {
  const pd = await publicData(w, id);
  let last: Record<string, any> = {};
  for (const r of ['alice', 'lawyerA', 'bob', 'lawyerB'] as Role[]) {
    const p = w.parties[r];
    last = ok(
      await post(w, id, r, 'pq.bound', {
        binding: {
          slot: p.slot,
          deal_seal: pd.dealSeal,
          slot_pub: pub(w, r),
          pq_key_hash: rndHex(32),
          holder_sigs: [0, 1].map((i) => ({ key_id: p.holders[i]?.pairId, sig: toBase64(new Uint8Array(3309)) })),
          cross_sig: rndHex(64),
        },
      }),
    );
  }
  return last;
}

export async function toKeysReady(w: World, id: string) {
  await toQuarantined(w, id);
  await pqBind(w, id);
}

/** The shell as rippled would show it after a correct lock (mirrors the core lock checker's own fixture). */
export function setGoodLock(w: World, domain: string) {
  const signers = (['alice', 'lawyerA', 'bob', 'lawyerB'] as Role[]).map((r) => account(w, r));
  w.ledger.accounts.set(w.addr.shell, {
    accountData: {
      Account: w.addr.shell,
      Flags:
        lsf.DisableMaster |
        lsf.DepositAuth |
        lsf.DisallowIncomingNFTokenOffer |
        lsf.DisallowIncomingCheck |
        lsf.DisallowIncomingPayChan |
        lsf.DisallowIncomingTrustline,
      Domain: domain,
      OwnerCount: 2,
      Sequence: 41,
    },
    objects: [
      {
        LedgerEntryType: 'SignerList',
        SignerQuorum: 4,
        SignerEntries: signers.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
        index: 'S1',
      },
      { LedgerEntryType: 'DepositPreauth', Account: w.addr.shell, Authorize: w.addr.opsB, index: 'P1' },
      {
        LedgerEntryType: 'Credential',
        Issuer: w.addr.shell,
        Subject: account(w, 'alice'),
        Flags: lsf.CredentialAccepted,
        index: 'C1',
      },
      {
        LedgerEntryType: 'Credential',
        Issuer: w.addr.shell,
        Subject: account(w, 'bob'),
        Flags: lsf.CredentialAccepted,
        index: 'C2',
      },
      {
        LedgerEntryType: 'Escrow',
        Account: account(w, 'alice'),
        Destination: w.addr.shell,
        Sequence: 7,
        Amount: AMOUNT,
        Condition: CONDITION,
        CancelAfter: w.ledger.closeTime + 200_000,
        index: 'E1',
      },
    ],
  });
}

export async function toVerified(w: World, id: string) {
  await toKeysReady(w, id);
  const pd = await publicData(w, id);
  setGoodLock(w, pd.domain);
  ok(
    await post(w, id, 'alice', 'wallet.locked', {
      tx_hashes: [addTx(w, 'AccountSet', w.addr.shell)],
      domain: pd.domain,
    }),
  );
  const l = await w.ledger.validatedLedger();
  ok(
    await post(w, id, 'lawyerB', 'lock.verified', {
      ledger: { ledger_index: l.ledgerIndex, ledger_hash: l.ledgerHash },
      findings: [],
    }),
  );
}

export const gateRecord = (w: World, id: string, dealSeal: string) => ({
  deal_id: id,
  deal_seal: dealSeal,
  ledger: {
    ledger_index: w.ledger.index,
    ledger_hash: (w.ledger as { hash?: (i: number) => string }).hash?.(w.ledger.index) ?? 'AB'.repeat(32),
  },
  findings: GATE_CODES.map((code) => ({ ok: true, level: 'block', code })),
  relied_on: [{ name: 'lock', sha256: rndHex(32) }],
  slot_lb_sig: rndHex(64),
});

export async function gatePassed(w: World, id: string) {
  const pd = await publicData(w, id);
  return post(w, id, 'lawyerB', 'release.gate.passed', { gate: gateRecord(w, id, pd.dealSeal) });
}

export async function toFunded(w: World, id: string) {
  await toVerified(w, id);
  const g = ok(await gatePassed(w, id));
  const finish = addTx(w, 'EscrowFinish', w.addr.opsB, ourEscrow(w));
  w.ledger.index += 0;
  ok(
    await post(w, id, 'lawyerB', 'release.performed', {
      finish_tx_hash: finish,
      ledger_index: w.ledger.index,
      gate_leaf_hash: g.leafHash,
    }),
  );
}
