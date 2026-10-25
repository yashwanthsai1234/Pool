// T-U-21 inputs in the browser: the ZF frost-ed25519 vectors (vectors.json carries the RFC 9591 Appendix E.1 values:
// participants 1 and 3, message "test") through core's signing wrapper, in Chromium and WebKit.
// Source: https://www.rfc-editor.org/rfc/rfc9591#appendix-E.1
import {
  aggregateChecked,
  Fn,
  holderId,
  mulBase,
  parseScalar,
  SigningSession,
  type SlotPublic,
  scalarBytes,
} from '@legx/core/frost';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import rfc from '../../../../tools/frost-ref/vectors/zf-vectors.json';
import big from '../../../../tools/frost-ref/vectors/zf-vectors-big-identifier.json';

type Vector = typeof rfc;

function replay(v: Vector) {
  const a0 = parseScalar(hexToBytes(v.inputs.group_secret_key));
  const a1 = parseScalar(hexToBytes(v.inputs.share_polynomial_coefficients[0] as string));
  const share = (i: number) => scalarBytes(Fn.add(a0, Fn.mul(a1, BigInt(i))));
  const ids = v.inputs.participant_list;
  const pub: SlotPublic = {
    signers: { min: 2, max: Number(v.config.MAX_PARTICIPANTS) },
    commitments: [hexToBytes(v.inputs.verifying_key_key)],
    verifyingShares: Object.fromEntries(ids.map((i) => [holderId(i), mulBase(parseScalar(share(i))).toBytes()])),
  };
  const msg = hexToBytes(v.inputs.message);
  const r1 = v.round_one_outputs.outputs;
  const sessions = ids.map((i) => {
    const o = r1.find((x) => x.identifier === i) as (typeof r1)[number];
    const queue = [hexToBytes(o.hiding_nonce_randomness), hexToBytes(o.binding_nonce_randomness)];
    return SigningSession.open(
      { identifier: holderId(i), signingShare: share(i) },
      pub,
      msg,
      () => queue.shift() as Uint8Array,
    );
  });
  const list = sessions.map((s) => s.commitment);
  ids.forEach((i, k) => {
    const o = r1.find((x) => x.identifier === i) as (typeof r1)[number];
    expect(bytesToHex(list[k]?.hiding as Uint8Array)).toBe(o.hiding_nonce_commitment);
    expect(bytesToHex(list[k]?.binding as Uint8Array)).toBe(o.binding_nonce_commitment);
  });
  const shares = Object.fromEntries(
    ids.map((i, k) => [holderId(i), (sessions[k] as SigningSession).signShare(msg, list, () => ({ ok: true }))]),
  );
  for (const o of v.round_two_outputs.outputs)
    expect(bytesToHex(shares[holderId(o.identifier)] as Uint8Array)).toBe(o.sig_share);
  expect(bytesToHex(aggregateChecked(pub, list, msg, shares))).toBe(v.final_output.sig);
}

describe('T-U-21 FROST vectors in the browser', () => {
  it('RFC 9591 E.1 values (ZF vectors.json)', () => replay(rfc));
  it('ZF vectors-big-identifier.json', () => replay(big as Vector));
});
