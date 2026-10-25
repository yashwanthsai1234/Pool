// The verifier pipeline (DESIGN 6.16, D19, D23): account_info, then verify and sign, then 0a, then 0b, then events.
// Every step is idempotent because it first asks the ledger or the database what is already done, so a crash at any
// point is resumed by running the same call again (the pg-boss job in jobs.ts does exactly that).
import type { BarRegistryAdapter, LedgerPort, SignerPort, XrplJson } from '@legx/contracts/ports';
import { BarDealLink, BarVerification } from '@legx/contracts/records';
import { Hex32, XrplAddress, XrplEd25519PublicKey } from '@legx/contracts/values';
import { BAR_MAX_AGE_SECONDS, barNumberSha256, openBarCommitment, verifyBarDealLink } from '@legx/core/bar';
import type { Database } from '@legx/db';
import { build0a, build0b, build0c } from '@legx/xrpl';
import { hexOfText, hexUp } from '@legx/xrpl/builders/common';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { credentialHashes, readOpsState } from './chain.ts';
import { VerifierError } from './errors.ts';
import { signAttestation, verifierTrust } from './signing.ts';

/** An XRPL account key held outside this service (KMS, or the lawyer's console for the operations account). */
export interface AccountSigner {
  /** Signs an autofilled transaction and returns the blob. */
  sign(tx: XrplJson): Promise<string>;
}

export type Log = (event: string, fields: Readonly<Record<string, unknown>>) => void;

export interface VerifierDeps {
  readonly db: Database;
  readonly ledger: LedgerPort;
  /** The verifier attestation key (hybrid). */
  readonly signer: SignerPort;
  readonly issuer: { readonly address: string; readonly signer: AccountSigner };
  /** One adapter per jurisdiction. */
  readonly adapters: ReadonlyMap<string, BarRegistryAdapter>;
  /**
   * Signs step 0b with the lawyer's operations account key (only the lawyer holds it). Returns undefined while the
   * lawyer has not done it yet; the onboarding then reports `awaiting_ops_accept` and is retried.
   */
  readonly opsAccept?: (tx: XrplJson) => Promise<string | undefined>;
  /** Default 30 days (D19). Tests on a standalone ledger, which cannot jump time, use seconds. */
  readonly maxAgeSeconds?: number;
  readonly log?: Log;
}

export interface OnboardInput {
  readonly opsAccount: string;
  readonly jurisdiction: string;
  readonly barNumber: string; // Secret: used for the lookup and never stored or logged
}

export type OnboardResult =
  | {
      readonly state: 'complete';
      readonly verificationSha256: string;
      readonly createTxHash: string;
      readonly acceptTxHash: string;
      readonly expiration: number;
    }
  | { readonly state: 'awaiting_ops_accept'; readonly verificationSha256: string };

export interface LinkInput {
  readonly dealId: string;
  readonly contractRoot: string; // hex32
  readonly role: 'LA' | 'LB';
  readonly lawyerPub: string;
  readonly opsAccount: string;
  readonly barNumber: string; // Secret
  readonly salt: Uint8Array; // Secret: zeroed before `link` returns
  readonly barCommitment: string; // the sealed LC_role, hex32
}

const ALGS = ['ed25519', 'ml-dsa-65'] as const;

const asRole = (r: 'LA' | 'LB') => (r === 'LA' ? 'lawyerA' : 'lawyerB');

export function createVerifier(d: VerifierDeps) {
  const maxAge = d.maxAgeSeconds ?? BAR_MAX_AGE_SECONDS;
  const log: Log = d.log ?? (() => undefined);
  const issuer = XrplAddress.parse(d.issuer.address);

  async function submit(
    label: string,
    build: (ctx: { network: never; baseFeeDrops: number }) => object,
    who: AccountSigner,
  ) {
    const fees = await d.ledger.fees();
    const tx = build({ network: d.ledger.network as never, baseFeeDrops: Number(fees.baseFee) });
    const blob = await who.sign(await d.ledger.autofill(tx as XrplJson, 0));
    const r = await d.ledger.submitReliable(blob);
    if (r.status === 'expired') throw new VerifierError('LEDGER_EXPIRED', `${label} passed its LastLedgerSequence`);
    if (r.status === 'rejected' || r.result !== 'tesSUCCESS') {
      throw new VerifierError('LEDGER_REJECTED', `${label}: ${r.result}`);
    }
    log('ledger.step', { label, hash: r.hash, ledgerIndex: r.ledgerIndex });
  }

  // Every signature is also an evidence event (the verifier key is the root of lawyer trust).
  async function signed(recordType: 'BarVerification' | 'BarDealLink', payload: object) {
    const s = await signAttestation(d.signer, payload);
    const note = { record_type: recordType, sha256: s.sha256, key_ids: s.keyIds };
    await d.db.repos.outbox.enqueue({ topic: 'verifier.signed', payload: utf8ToBytes(JSON.stringify(note)) });
    log('verifier.signed', note);
    return s;
  }

  // The newest active verification of this lawyer that is still within the age limit, by ledger time.
  async function freshVerification(ops: string, barHash: string, jurisdiction: string, now: number) {
    const lawyer = await d.db.repos.lawyers.get(ops);
    if (!lawyer) return undefined;
    if (lawyer.bar_number_sha256 !== barHash || lawyer.jurisdiction !== jurisdiction) {
      throw new VerifierError('BAR_NUMBER_MISMATCH', `${ops} was onboarded with a different bar number`);
    }
    return await latestFresh(ops, now);
  }

  async function latestFresh(ops: string, now: number) {
    const newest = (await d.db.repos.barVerifications.listFor(ops))[0];
    if (newest?.status !== 'active') return undefined;
    const at = await d.ledger.ledgerHeader(newest.checked_at_ledger);
    return now - at.closeTime <= maxAge ? newest : undefined;
  }

  const deleteCredential = (label: string, subject: string) =>
    submit(label, (c) => build0c({ issuer, subject }, c), d.issuer.signer);

  /** Steps 1 and 2: `account_info`, then the registry lookup, then the signed BarVerification. Needs the bar number. */
  async function verify(i: OnboardInput) {
    const ops = XrplAddress.parse(i.opsAccount);
    const adapter = d.adapters.get(i.jurisdiction);
    if (!adapter) throw new VerifierError('NO_ADAPTER', `no registry adapter for ${i.jurisdiction}`);
    let barHash: string;
    try {
      barHash = barNumberSha256(i.barNumber);
    } catch (e) {
      throw new VerifierError('ADAPTER_BAD_REQUEST', (e as Error).message);
    }
    const state = await readOpsState(d.ledger, ops, issuer); // first ledger call: refuses before anything is issued
    const fresh = await freshVerification(ops, barHash, i.jurisdiction, state.ledger.closeTime);
    if (fresh) return fresh;
    const lawyer = await d.db.repos.lawyers.get(ops);
    if (lawyer && (lawyer.bar_number_sha256 !== barHash || lawyer.jurisdiction !== i.jurisdiction)) {
      throw new VerifierError('BAR_NUMBER_MISMATCH', `${ops} was onboarded with a different bar number`);
    }
    const found = await adapter.lookup({ jurisdiction: i.jurisdiction, barNumber: i.barNumber as never });
    if (found.status !== 'active') {
      if (state.credential) await deleteCredential('CredentialDelete (revoke)', ops);
      throw new VerifierError(
        found.status === 'not_found' ? 'NOT_FOUND' : 'NOT_ACTIVE',
        `bar status is ${found.status}`,
      );
    }
    const keys = await d.signer.publicKeys();
    const payload = BarVerification.parse({
      jurisdiction: i.jurisdiction,
      bar_number_sha256: barHash,
      status: 'active',
      source: { kind: found.source.kind, url: found.source.url, evidence_sha256: found.source.evidenceSha256 },
      ops_account: ops,
      checked_at_ledger: { ledger_index: state.ledger.ledgerIndex, ledger_hash: state.ledger.ledgerHash },
      verifier_key_id: keys.keyIds.ed25519,
      sig_algs: [...ALGS],
    });
    const s = await signed('BarVerification', payload);
    await d.db.repos.lawyers.insert({ ops_account: ops, jurisdiction: i.jurisdiction, bar_number_sha256: barHash });
    return await d.db.repos.barVerifications.insert({
      envelope_sha256: s.sha256,
      ops_account: ops,
      envelope: s.bytes,
      status: 'active',
      checked_at_ledger: state.ledger.ledgerIndex,
      checked_at_ledger_hash: state.ledger.ledgerHash,
    });
  }

  /** Steps 3 to 5: 0a, 0b, then the credential row and the event. Carries no secret, so a job may hold its input. */
  async function issue(opsAccount: string): Promise<OnboardResult> {
    const ops = XrplAddress.parse(opsAccount);
    const start = await readOpsState(d.ledger, ops, issuer);
    const v = await latestFresh(ops, start.ledger.closeTime);
    if (!v) throw new VerifierError('VERIFICATION_STALE', `${ops} has no active verification within the age limit`);
    const want = hexOfText(`legx:bar:v1:${hexUp(Uint8Array.from(Buffer.from(v.envelope_sha256, 'hex')))}`);

    let state = start;
    const c0 = state.credential;
    if (c0 && (c0.uri !== want || (c0.expiration !== undefined && c0.expiration <= state.ledger.closeTime))) {
      await deleteCredential('CredentialDelete', ops);
      state = await readOpsState(d.ledger, ops, issuer);
    }
    if (!state.credential) {
      const barVerificationSha256 = Uint8Array.from(Buffer.from(v.envelope_sha256, 'hex'));
      await submit(
        '0a CredentialCreate',
        (c) => build0a({ issuer, subject: ops, barVerificationSha256, closeTime: state.ledger.closeTime }, c),
        d.issuer.signer,
      );
      state = await readOpsState(d.ledger, ops, issuer);
    }
    if (!state.credential?.accepted) {
      const fees = await d.ledger.fees();
      const tx = build0b(
        { subject: ops, issuer },
        { network: d.ledger.network as never, baseFeeDrops: Number(fees.baseFee) },
      );
      const blob = await d.opsAccept?.(await d.ledger.autofill(tx as XrplJson, 0));
      if (!blob) return { state: 'awaiting_ops_accept', verificationSha256: v.envelope_sha256 };
      const r = await d.ledger.submitReliable(blob);
      if (r.status !== 'validated' || r.result !== 'tesSUCCESS') {
        throw new VerifierError(
          'LEDGER_REJECTED',
          `0b CredentialAccept: ${r.status === 'validated' ? r.result : r.status}`,
        );
      }
      state = await readOpsState(d.ledger, ops, issuer);
    }
    const cred = state.credential;
    if (!cred?.accepted || cred.expiration === undefined) {
      throw new VerifierError('LEDGER_REJECTED', 'the credential is not accepted after step 0b');
    }
    const hashes = await credentialHashes(d.ledger, cred);
    const known = await d.db.repos.attorneyCredentials.listFor(ops);
    if (!known.some((k) => k.create_tx_hash === hashes.createTxHash)) {
      await d.db.repos.attorneyCredentials.insert({
        ops_account: ops,
        verification_sha256: v.envelope_sha256,
        create_tx_hash: hashes.createTxHash,
        accept_tx_hash: hashes.acceptTxHash,
        expiration: cred.expiration,
      });
      const event = {
        ops_account: ops,
        verification_sha256: v.envelope_sha256,
        ...hashes,
        expiration: cred.expiration,
      };
      await d.db.repos.outbox.enqueue({ topic: 'bar.verified', payload: utf8ToBytes(JSON.stringify(event)) });
      log('bar.verified', event);
    }
    return { state: 'complete', verificationSha256: v.envelope_sha256, ...hashes, expiration: cred.expiration };
  }

  async function onboard(i: OnboardInput): Promise<OnboardResult> {
    await verify(i);
    return await issue(i.opsAccount);
  }

  /** After 30 days (or when the credential expired): the same pipeline, which deletes the old credential first. */
  async function reverify(i: OnboardInput): Promise<OnboardResult> {
    if (!(await d.db.repos.lawyers.get(i.opsAccount)))
      throw new VerifierError('NOT_ONBOARDED', `${i.opsAccount} was never onboarded`);
    return await onboard(i);
  }

  /**
   * The per-deal link (DESIGN 6.16): the lawyer sends the bar number and this deal's salt. The service opens the sealed
   * LC_role against the bar number it verified, signs the BarDealLink, checks it as the gate would, and forgets the salt.
   */
  async function link(i: LinkInput): Promise<Uint8Array> {
    try {
      const ops = XrplAddress.parse(i.opsAccount);
      const lawyer = await d.db.repos.lawyers.get(ops);
      if (!lawyer) throw new VerifierError('NOT_ONBOARDED', `${ops} was never onboarded`);
      let barHash: string;
      try {
        barHash = barNumberSha256(i.barNumber);
      } catch (e) {
        throw new VerifierError('ADAPTER_BAD_REQUEST', (e as Error).message);
      }
      if (barHash !== lawyer.bar_number_sha256)
        throw new VerifierError('BAR_NUMBER_MISMATCH', 'not the verified bar number');
      const lc = Buffer.from(openBarCommitment(i.salt, lawyer.jurisdiction, i.barNumber)).toString('hex');
      if (lc !== i.barCommitment)
        throw new VerifierError('COMMITMENT_MISMATCH', 'the salt does not open the sealed commitment');
      const now = await d.ledger.validatedLedger();
      const v = await latestFresh(ops, now.closeTime);
      if (!v) throw new VerifierError('VERIFICATION_STALE', 'verify the lawyer again before linking');
      const have = (await d.db.repos.barDealLinks.list(i.dealId)).find(
        (l) => l.role === asRole(i.role) && l.verification_sha256 === v.envelope_sha256,
      );
      if (have) return have.envelope;
      const payload = BarDealLink.parse({
        deal_id: i.dealId,
        contract_root: Hex32.parse(i.contractRoot),
        role: i.role,
        lawyer_pub: XrplEd25519PublicKey.parse(i.lawyerPub),
        bar_commitment: Hex32.parse(i.barCommitment),
        ops_account: ops,
        verification_sha256: v.envelope_sha256,
        sig_algs: [...ALGS],
      });
      const s = await signed('BarDealLink', payload);
      const check = verifyBarDealLink({
        linkBytes: s.bytes,
        verificationBytes: v.envelope,
        trust: await verifierTrust(d.signer),
        sealed: {
          dealId: i.dealId,
          contractRoot: i.contractRoot,
          role: i.role,
          lawyerPub: i.lawyerPub,
          barCommitment: i.barCommitment,
          opsAccount: ops,
        },
        checkedAtCloseTime: (await d.ledger.ledgerHeader(v.checked_at_ledger)).closeTime,
        nowCloseTime: now.closeTime,
        opening: { salt32: i.salt, barNumber: i.barNumber },
      });
      if (!check.ok)
        throw new VerifierError('SELF_CHECK_FAILED', `the new link does not pass the gate check: ${check.code}`);
      await d.db.repos.barDealLinks.insert({
        deal_id: i.dealId,
        role: asRole(i.role),
        envelope: s.bytes,
        verification_sha256: v.envelope_sha256,
      });
      return s.bytes;
    } finally {
      i.salt.fill(0); // the salt lives only in this call
    }
  }

  return { verify, issue, onboard, reverify, link };
}

export type Verifier = ReturnType<typeof createVerifier>;
