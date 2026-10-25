// Task 1.7: operations-account binding (DESIGN 6.14, IMPLEMENTATION 1.7).
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import {
  type AccountInfo,
  LSF_DISABLE_MASTER,
  type OpsBinding,
  opsBindMsg,
  verifyOpsBinding,
} from '../src/opsBinding.ts';
import { pyVector } from './helpers/pyref.ts';

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();

// Signs `msg` the way an XRPL account key signs (DESIGN 6.8): Ed25519 over the bytes, or secp256k1 DER over SHA-512Half.
function signWith(w: xrpl.Wallet, msg: Uint8Array): string {
  const sk = hexToBytes(w.privateKey.slice(2));
  if (w.publicKey.startsWith('ED')) return up(ed25519.sign(msg, sk));
  return up(secp256k1.sign(sha512(msg).subarray(0, 32), sk, { prehash: false, format: 'der' }));
}

const ROOT = new Uint8Array(32).fill(0x21);
const LC = new Uint8Array(32).fill(0x22);

function bind(opts: { ops: xrpl.Wallet; account?: string; lawyer?: xrpl.Wallet; role?: 'LA' | 'LB' }): OpsBinding {
  const lawyer = opts.lawyer ?? xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
  const sealed = {
    contractRoot: ROOT,
    opsAccount: opts.account ?? opts.ops.classicAddress,
    lawyerPub: lawyer.publicKey,
    lawyerCommitment: LC,
    role: opts.role ?? 'LA',
  };
  const msg = opsBindMsg(sealed);
  return { ...sealed, opsPub: opts.ops.publicKey, opsSig: signWith(opts.ops, msg), lawyerSig: signWith(lawyer, msg) };
}

const info = (Account: string, Flags = 0, RegularKey?: string): AccountInfo => ({
  validated: true,
  account_data: { Account, Flags, ...(RegularKey ? { RegularKey } : {}) },
});

describe('T-U-19 verifyOpsBinding', () => {
  it('T-U-19a Ed25519 operations account, master key on: passes', () => {
    const ops = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    expect(verifyOpsBinding(info(ops.classicAddress), bind({ ops }))).toEqual({ ok: true });
  });

  it('T-U-19b secp256k1 operations account: passes', () => {
    const ops = xrpl.Wallet.generate(xrpl.ECDSA.secp256k1);
    expect(verifyOpsBinding(info(ops.classicAddress), bind({ ops }))).toEqual({ ok: true });
  });

  it("T-U-19c the operations key is the account's RegularKey and the master key is off: passes", () => {
    const account = xrpl.Wallet.generate().classicAddress;
    for (const algo of [xrpl.ECDSA.ed25519, xrpl.ECDSA.secp256k1]) {
      const regular = xrpl.Wallet.generate(algo);
      const b = bind({ ops: regular, account });
      expect(verifyOpsBinding(info(account, LSF_DISABLE_MASTER, regular.classicAddress), b)).toEqual({ ok: true });
      expect(verifyOpsBinding(info(account, 0, regular.classicAddress), b)).toEqual({ ok: true }); // master on too
    }
  });

  it('T-U-19d a swapped operations account in the message fails', () => {
    const opsA = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const opsB = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const b = bind({ ops: opsA });
    // The binding names opsB but carries opsA's signatures: the account read does not match the sealed account,
    // and against opsB's own account info the signatures do not cover opsB.
    expect(verifyOpsBinding(info(opsA.classicAddress), { ...b, opsAccount: opsB.classicAddress })).toEqual({
      ok: false,
      code: 'ACCOUNT_MISMATCH',
    });
    expect(verifyOpsBinding(info(opsB.classicAddress), { ...b, opsAccount: opsB.classicAddress })).toEqual({
      ok: false,
      code: 'OPS_KEY_NOT_AUTHORIZED',
    });
    const signedForB = bind({ ops: opsA, account: opsB.classicAddress });
    expect(
      verifyOpsBinding(info(opsB.classicAddress, 0, opsA.classicAddress), {
        ...signedForB,
        opsAccount: opsA.classicAddress,
      }),
    ).toEqual({
      ok: false,
      code: 'ACCOUNT_MISMATCH',
    });
  });

  it('T-U-19e a key that is neither the master key (master on) nor the RegularKey fails', () => {
    const account = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const stranger = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const regular = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const b = bind({ ops: stranger, account: account.classicAddress });
    expect(verifyOpsBinding(info(account.classicAddress), b)).toEqual({ ok: false, code: 'OPS_KEY_NOT_AUTHORIZED' });
    expect(verifyOpsBinding(info(account.classicAddress, 0, regular.classicAddress), b)).toEqual({
      ok: false,
      code: 'OPS_KEY_NOT_AUTHORIZED',
    });
  });

  it('P1.7-01 the master key signs but lsfDisableMaster is set: fails', () => {
    const ops = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const regular = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const b = bind({ ops });
    expect(verifyOpsBinding(info(ops.classicAddress, LSF_DISABLE_MASTER, regular.classicAddress), b)).toEqual({
      ok: false,
      code: 'OPS_KEY_NOT_AUTHORIZED',
    });
    // Other flags set next to lsfDisableMaster change nothing; other flags alone keep the master key on.
    const flags = LSF_DISABLE_MASTER | 0x00010000 | 0x00800000;
    expect(verifyOpsBinding(info(ops.classicAddress, flags), b).ok).toBe(false);
    expect(verifyOpsBinding(info(ops.classicAddress, 0x00010000 | 0x00800000), b).ok).toBe(true);
  });

  it("P1.7-02 a missing lawyer signature, or one by another lawyer's key, fails", () => {
    const ops = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const other = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const b = bind({ ops });
    const i = info(ops.classicAddress);
    expect(verifyOpsBinding(i, { ...b, lawyerSig: '' })).toEqual({ ok: false, code: 'LAWYER_SIG_INVALID' });
    expect(verifyOpsBinding(i, { ...b, lawyerSig: signWith(other, opsBindMsg(b)) })).toEqual({
      ok: false,
      code: 'LAWYER_SIG_INVALID',
    });
  });

  it('a bad operations signature and an unvalidated account_info fail', () => {
    const ops = xrpl.Wallet.generate(xrpl.ECDSA.secp256k1);
    const b = bind({ ops });
    expect(verifyOpsBinding(info(ops.classicAddress), { ...b, opsSig: '' })).toEqual({
      ok: false,
      code: 'OPS_SIG_INVALID',
    });
    expect(verifyOpsBinding({ ...info(ops.classicAddress), validated: false }, b)).toEqual({
      ok: false,
      code: 'NOT_VALIDATED',
    });
    for (const lawyerPub of ['', 'zz', `02${'11'.repeat(32)}`])
      expect(verifyOpsBinding(info(ops.classicAddress), { ...b, lawyerPub })).toEqual({
        ok: false,
        code: 'LAWYER_SIG_INVALID',
      });
    expect(verifyOpsBinding(info(ops.classicAddress), { ...b, opsPub: 'zz' })).toEqual({
      ok: false,
      code: 'OPS_KEY_NOT_AUTHORIZED',
    });
  });
});

describe('opsBindMsg', () => {
  it('matches tools/py-ref/vectors/ops_bind.json', () => {
    const v = pyVector('ops_bind', 'opsBindMsg');
    const msg = opsBindMsg({
      contractRoot: hexToBytes(v.inputs.root as string),
      opsAccount: v.inputs.ops as string,
      lawyerPub: v.inputs.lawyerPub as string,
      lawyerCommitment: hexToBytes(v.inputs.LC as string),
      role: v.inputs.role as 'LA',
    });
    expect(bytesToHex(msg)).toBe(v.output);
  });
});

describe('properties', () => {
  const algo = fc.constantFrom(xrpl.ECDSA.ed25519, xrpl.ECDSA.secp256k1);
  const kind = fc.constantFrom('master', 'regular');

  it('random account types pass; any single swapped field fails', () => {
    fc.assert(
      fc.property(algo, kind, fc.constantFrom('LA' as const, 'LB' as const), fc.nat(), (a, k, role, n) => {
        const ops = xrpl.Wallet.generate(a);
        const account = k === 'master' ? ops.classicAddress : xrpl.Wallet.generate().classicAddress;
        const b = bind({ ops, account, role });
        const i = k === 'master' ? info(account) : info(account, LSF_DISABLE_MASTER, ops.classicAddress);
        expect(verifyOpsBinding(i, b)).toEqual({ ok: true });
        const other = xrpl.Wallet.generate(a);
        const flip = (x: Uint8Array) => {
          const c = x.slice();
          c[n % 32] = (c[n % 32] ?? 0) ^ 1;
          return c;
        };
        const mutants: OpsBinding[] = [
          { ...b, contractRoot: flip(b.contractRoot) },
          { ...b, lawyerCommitment: flip(b.lawyerCommitment) },
          { ...b, role: role === 'LA' ? 'LB' : 'LA' },
          { ...b, lawyerPub: xrpl.Wallet.generate(xrpl.ECDSA.ed25519).publicKey },
          { ...b, opsPub: other.publicKey },
          { ...b, opsSig: b.lawyerSig },
          { ...b, lawyerSig: b.opsSig },
        ];
        for (const m of mutants) expect(verifyOpsBinding(i, m).ok).toBe(false);
      }),
      { numRuns: 40 },
    );
  });

  it('differential: xrpl.js verifyKeypairSignature agrees on every honest binding signature', () => {
    fc.assert(
      fc.property(algo, (a) => {
        const ops = xrpl.Wallet.generate(a);
        const b = bind({ ops });
        const msgHex = bytesToHex(opsBindMsg(b));
        expect(xrpl.verifyKeypairSignature(msgHex, b.opsSig, b.opsPub)).toBe(true);
        expect(xrpl.verifyKeypairSignature(msgHex, b.lawyerSig, b.lawyerPub)).toBe(true);
        expect(verifyOpsBinding(info(ops.classicAddress), b)).toEqual({ ok: true });
      }),
      { numRuns: 20 },
    );
  });
});
