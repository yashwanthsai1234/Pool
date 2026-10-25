// P3.9-19: the allow-list. A holder decodes the exact message itself and signs only what the sealed deal allows.
import { bytesToHex, sha256, utf8ToBytes } from '@legx/core/dealcore';
import type { SealedDeal } from '@legx/core/frostRules';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { describe, expect, it } from 'vitest';
import { deriveAddress, ECDSA, encodeForMultiSigning, Wallet } from 'xrpl';
import type { SignBegin } from '../src/holder.ts';
import { cosignCheck, GATE_RECORD_TAG, taggedMessage } from '../src/policy.ts';
import { rnd } from './support/world.ts';

const slotPub = (): Uint8Array => new Uint8Array([0xed, ...ed25519.getPublicKey(ed25519.utils.randomSecretKey())]);
const wallet = Wallet.generate(ECDSA.ed25519).classicAddress;
const pays = [Wallet.generate(ECDSA.ed25519).classicAddress, Wallet.generate(ECDSA.ed25519).classicAddress];
const deal: SealedDeal = {
  walletAddress: wallet,
  contractRoot: rnd(32),
  dealSeal: rnd(32),
  payoutA: { account: pays[0] as string, tag: 7 },
  payoutB: { account: pays[1] as string },
  exitAmountDrops: '5000000000',
  maxFeeDrops: '1000',
  slotPubs: { A: slotPub(), B: slotPub(), LA: slotPub(), LB: slotPub() },
};
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const ctx = (begin: Partial<SignBegin>) => ({ request: undefined, begin: begin as SignBegin });

function tagged(tag: string, parts: Uint8Array[], slot: 'A' | 'LA' | 'LB', role: 'phone' | 'firm-hsm' = 'phone') {
  const msg = taggedMessage(tag, parts);
  const check = cosignCheck(deal, slot, role);
  return check(msg, [], ctx({ message_kind: 'tagged', tagged: { tag, parts: parts.map(hex) } })).ok;
}

describe('P3.9-19 the allow-list', () => {
  it('signs the messages DESIGN 6.4 lists, for the right slot', () => {
    const A = deal.slotPubs.A;
    expect(tagged('legx/binding/v1', [deal.contractRoot, rnd(32), A, utf8ToBytes('A')], 'A')).toBe(true); // bindings
    expect(
      tagged('legx/passport-presence/v1', [deal.dealSeal as Uint8Array, utf8ToBytes('A'), rnd(32), rnd(32)], 'A'),
    ).toBe(true); // presence
    expect(tagged('legx/pq-binding/v1', [deal.dealSeal as Uint8Array, A, rnd(32)], 'A')).toBe(true); // post-quantum cross-signature
    const LA = deal.slotPubs.LA;
    expect(tagged('legx/contract-sign/v1', [deal.contractRoot, utf8ToBytes(wallet), utf8ToBytes('LA')], 'LA')).toBe(
      true,
    ); // contract signature
    expect(
      tagged('legx/ops-binding/v1', [deal.contractRoot, utf8ToBytes('rOps'), LA, rnd(32), utf8ToBytes('LA')], 'LA'),
    ).toBe(true); // operations binding
  });

  it('signs a gate record for lawyer B only', () => {
    const statement = {
      predicate: { kind: 'release.gate.passed' },
      subject: [{ digest: { sha256: bytesToHex(deal.contractRoot) } }],
    };
    const envelope = utf8ToBytes(
      JSON.stringify({
        payloadType: 'application/vnd.legx.event+json;v=1',
        payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
      }),
    );
    expect(tagged(GATE_RECORD_TAG, [envelope], 'LB', 'phone')).toBe(true);
    expect(tagged(GATE_RECORD_TAG, [envelope], 'LA', 'phone')).toBe(false);
    expect(tagged(GATE_RECORD_TAG, [envelope], 'A', 'phone')).toBe(false);
    expect(hex(taggedMessage(GATE_RECORD_TAG, [envelope]))).toBe(hex(sha256(envelope)));
  });

  it('refuses an unknown tag, a known tag with other parts, and a tag meant for the other kind of slot', () => {
    expect(tagged('legx/unknown/v1', [rnd(32)], 'A')).toBe(false);
    expect(tagged('legx/binding/v1', [rnd(32), rnd(32), deal.slotPubs.A, utf8ToBytes('A')], 'A')).toBe(false); // wrong contract root
    expect(tagged('legx/binding/v1', [deal.contractRoot, rnd(32), deal.slotPubs.B, utf8ToBytes('A')], 'A')).toBe(false); // another slot's key
    expect(tagged('legx/contract-sign/v1', [deal.contractRoot, utf8ToBytes(wallet), utf8ToBytes('A')], 'A')).toBe(
      false,
    );
    expect(
      tagged('legx/passport-presence/v1', [deal.dealSeal as Uint8Array, utf8ToBytes('LA'), rnd(32), rnd(32)], 'LA'),
    ).toBe(false);
    // a tagged message with no preimage cannot be decoded, so it is refused
    expect(cosignCheck(deal, 'A', 'phone')(rnd(32), [], ctx({ message_kind: 'tagged' })).ok).toBe(false);
    // a holder that signs exits only refuses every tagged message
    const only = cosignCheck(deal, 'A', 'recovery-agent', { exitsOnly: true });
    const parts = [deal.contractRoot, rnd(32), deal.slotPubs.A, utf8ToBytes('A')];
    expect(
      only(
        taggedMessage('legx/binding/v1', parts),
        [],
        ctx({ message_kind: 'tagged', tagged: { tag: 'legx/binding/v1', parts: parts.map(hex) } }),
      ).ok,
    ).toBe(false);
  });

  it('signs the sealed exit and refuses any other transaction', () => {
    const signer = deriveAddress(bytesToHex(deal.slotPubs.A).toUpperCase());
    const msgOf = (tx: Record<string, unknown>) =>
      new Uint8Array(Buffer.from(encodeForMultiSigning(tx as never, signer), 'hex'));
    const exit = {
      TransactionType: 'Payment',
      Account: wallet,
      Destination: pays[1],
      Amount: '5000000000',
      Fee: '120',
      Sequence: 5,
      SigningPubKey: '',
    };
    const check = cosignCheck(deal, 'A', 'phone');
    const run = (tx: Record<string, unknown>) => check(msgOf(tx), [], ctx({ message_kind: 'xrpl-multisign' })).ok;
    expect(run(exit)).toBe(true);
    expect(run({ ...exit, Destination: Wallet.generate(ECDSA.ed25519).classicAddress })).toBe(false);
    expect(run({ ...exit, Amount: '5000000001' })).toBe(false);
    expect(run({ ...exit, Account: Wallet.generate(ECDSA.ed25519).classicAddress })).toBe(false);
    expect(run({ ...exit, Fee: '100000' })).toBe(false);
    expect(
      run({ TransactionType: 'AccountSet', Account: wallet, Fee: '120', Sequence: 5, SigningPubKey: '', SetFlag: 4 }),
    ).toBe(false);
    expect(
      run({
        TransactionType: 'SignerListSet',
        Account: wallet,
        Fee: '120',
        Sequence: 5,
        SigningPubKey: '',
        SignerQuorum: 1,
      }),
    ).toBe(false);
    // bytes that are not an XRPL multisign message at all
    expect(check(rnd(40), [], ctx({ message_kind: 'xrpl-multisign' })).ok).toBe(false);
  });

  it('T-U-31a: a holder that needs an approval refuses a missing, non-verified or wrong-hash one, and signs with a good one', () => {
    const key = p256.utils.randomSecretKey();
    const approver = { p256Pub: p256.getPublicKey(key), rpId: 'legx.example' };
    const exit = {
      TransactionType: 'Payment',
      Account: wallet,
      Destination: pays[1],
      Amount: '5000000000',
      Fee: '120',
      Sequence: 5,
      SigningPubKey: '',
    };
    const signer = deriveAddress(bytesToHex(deal.slotPubs.A).toUpperCase());
    const msg = new Uint8Array(Buffer.from(encodeForMultiSigning(exit as never, signer), 'hex'));
    const assertion = (hash: Uint8Array, uv = true) => {
      const authenticatorData = new Uint8Array([
        ...sha256(utf8ToBytes(approver.rpId)),
        0x01 | (uv ? 0x04 : 0),
        0,
        0,
        0,
        1,
      ]);
      const clientDataJSON = utf8ToBytes(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: Buffer.from(hash).toString('base64url'),
          origin: 'https://legx.example',
        }),
      );
      const signature = p256.sign(new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]), key, {
        format: 'der',
      });
      return {
        credential_id: 'AAAA',
        authenticator_data: Buffer.from(authenticatorData).toString('base64'),
        client_data_json: Buffer.from(clientDataJSON).toString('base64'),
        signature: Buffer.from(signature).toString('base64'),
        message_hash: hex(hash),
      };
    };
    const check = cosignCheck(deal, 'A', 'second-authenticator', { approver });
    const run = (approval?: ReturnType<typeof assertion>) =>
      check(msg, [], ctx({ message_kind: 'xrpl-multisign', ...(approval ? { approval: approval as never } : {}) }));
    expect(run()).toEqual({ ok: false, reason: 'APPROVAL_MISSING' });
    expect(run(assertion(sha256(msg), false))).toEqual({ ok: false, reason: 'APPROVAL_NOT_UV' });
    expect(run(assertion(sha256(utf8ToBytes('other'))))).toEqual({ ok: false, reason: 'APPROVAL_HASH_MISMATCH' });
    expect(run(assertion(sha256(msg)))).toEqual({ ok: true });
  });
});
