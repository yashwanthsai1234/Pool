// Task 1.5: signed-contract seal and mint memo (DESIGN 6.12, IMPLEMENTATION 1.5).
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import {
  buildSignedContractSeal,
  type ContractTerms,
  contractSigMsg,
  decodeMintMemo,
  encodeMintMemo,
  MINT_MEMO_TYPE,
  type MintMemo,
  nftUri,
  signContract,
  verifySignedContract,
} from '../src/signedContract.ts';
import { pyVector } from './helpers/pyref.ts';

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const edPub = (seed: Uint8Array) => `ED${up(ed25519.getPublicKey(seed))}`;
const utf8 = (s: string) => new TextEncoder().encode(s);
const flipByte = (b: Uint8Array, i: number) => {
  const c = b.slice();
  c[i % c.length] = (c[i % c.length] ?? 0) ^ 0x01;
  return c;
};
const flipHexByte = (h: string, i: number) => up(flipByte(hexToBytes(h), i));

// A FROST signature is a plain Ed25519 signature (DESIGN 6.4), so a single Ed25519 key stands in for a lawyer slot.
const signer = (seed: Uint8Array) => async (msg: Uint8Array) => ed25519.sign(msg, seed);

async function makeDeal(seedA: Uint8Array, seedB: Uint8Array, contractRoot: Uint8Array, walletAddress: string) {
  const terms: ContractTerms = { contractRoot, walletAddress, lawyerPubA: edPub(seedA), lawyerPubB: edPub(seedB) };
  const sigLA = await signContract(signer(seedA), terms, 'LA');
  const sigLB = await signContract(signer(seedB), terms, 'LB');
  return { terms, sigLA, sigLB, ...buildSignedContractSeal(terms, { sigLA, sigLB }) };
}

const SEED_LA = new Uint8Array(32).fill(0xa1);
const SEED_LB = new Uint8Array(32).fill(0xb2);
const SEED_CLIENT = new Uint8Array(32).fill(0xc3);
const ROOT = new Uint8Array(32).fill(0x11);
const WALLET = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

describe('T-U-13 verifySignedContract', () => {
  it('T-U-13a passes with the sealed keys, the memo and the URI from buildSignedContractSeal', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    expect(verifySignedContract(d.terms, d.memoHex, d.uriHex)).toEqual({ ok: true });
  });

  it('T-U-13b one changed byte of root, wallet address, either key or either signature fails with its code', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const m = decodeMintMemo(d.memoHex);
    if (!m.ok) throw new Error('memo');
    const memoWith = (p: Partial<MintMemo>) => encodeMintMemo({ ...m.value, ...p });
    const check = (terms: ContractTerms, memoHex = d.memoHex) => verifySignedContract(terms, memoHex, d.uriHex);
    // The signatures cover root and wallet, so a changed sealed root or wallet breaks the LA signature first.
    expect(check({ ...d.terms, contractRoot: flipByte(ROOT, 7) })).toEqual({ ok: false, code: 'SIG_LA_INVALID' });
    expect(check({ ...d.terms, walletAddress: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi' })).toEqual({
      ok: false,
      code: 'SIG_LA_INVALID',
    });
    // A changed key, on the sealed side or in the memo, is a key that is not sealed.
    expect(check({ ...d.terms, lawyerPubA: flipHexByte(d.terms.lawyerPubA, 9) })).toEqual({
      ok: false,
      code: 'KEYS_NOT_SEALED',
    });
    expect(check({ ...d.terms, lawyerPubB: flipHexByte(d.terms.lawyerPubB, 9) })).toEqual({
      ok: false,
      code: 'KEYS_NOT_SEALED',
    });
    expect(check(d.terms, memoWith({ lawyerPubA: flipHexByte(m.value.lawyerPubA, 9) }))).toEqual({
      ok: false,
      code: 'KEYS_NOT_SEALED',
    });
    expect(check(d.terms, memoWith({ sigLA: flipByte(m.value.sigLA, 5) }))).toEqual({
      ok: false,
      code: 'SIG_LA_INVALID',
    });
    expect(check(d.terms, memoWith({ sigLB: flipByte(m.value.sigLB, 40) }))).toEqual({
      ok: false,
      code: 'SIG_LB_INVALID',
    });
  });

  it('T-U-13b a URI for another seal fails with SEAL_MISMATCH', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const other = await makeDeal(SEED_LA, SEED_LB, flipByte(ROOT, 0), WALLET);
    expect(verifySignedContract(d.terms, d.memoHex, other.uriHex)).toEqual({ ok: false, code: 'SEAL_MISMATCH' });
  });

  it('T-U-13c swapping LA and LB (keys and signatures) fails', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const swappedMemo = encodeMintMemo({
      lawyerPubA: d.terms.lawyerPubB,
      sigLA: d.sigLB,
      lawyerPubB: d.terms.lawyerPubA,
      sigLB: d.sigLA,
    });
    expect(verifySignedContract(d.terms, swappedMemo, d.uriHex)).toEqual({ ok: false, code: 'KEYS_NOT_SEALED' });
    const swappedTerms = { ...d.terms, lawyerPubA: d.terms.lawyerPubB, lawyerPubB: d.terms.lawyerPubA };
    // Even if the sealed keys are swapped too, each signature names its role, so neither verifies.
    expect(verifySignedContract(swappedTerms, swappedMemo, d.uriHex)).toEqual({ ok: false, code: 'SIG_LA_INVALID' });
  });

  it('T-U-13d a memo whose keys are not the sealed lawyer keys fails with KEYS_NOT_SEALED', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const stranger = await makeDeal(new Uint8Array(32).fill(0xd4), new Uint8Array(32).fill(0xe5), ROOT, WALLET);
    expect(verifySignedContract(d.terms, stranger.memoHex, stranger.uriHex)).toEqual({
      ok: false,
      code: 'KEYS_NOT_SEALED',
    });
  });

  it("T-U-13e a client's x-key signing in place of a lawyer fails with KEYS_NOT_SEALED", async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const clientTerms = { ...d.terms, lawyerPubB: edPub(SEED_CLIENT) };
    const clientSig = await signContract(signer(SEED_CLIENT), clientTerms, 'LB');
    const forged = buildSignedContractSeal(clientTerms, { sigLA: d.sigLA, sigLB: clientSig });
    expect(verifySignedContract(clientTerms, forged.memoHex, forged.uriHex).ok).toBe(true); // self-consistent...
    expect(verifySignedContract(d.terms, forged.memoHex, forged.uriHex)).toEqual({
      ok: false,
      code: 'KEYS_NOT_SEALED',
    });
  });

  it('a ZIP-215-only signature (small-order key) never passes, even when sealed', () => {
    const identity = `ED01${'00'.repeat(31)}`;
    const s = 987654321n;
    const sR = ed25519.Point.BASE.multiply(s).toBytes();
    const sS = hexToBytes(s.toString(16).padStart(64, '0')).reverse();
    const forgedSig = new Uint8Array([...sR, ...sS]);
    const terms: ContractTerms = {
      contractRoot: ROOT,
      walletAddress: WALLET,
      lawyerPubA: identity,
      lawyerPubB: identity,
    };
    const built = buildSignedContractSeal(terms, { sigLA: forgedSig, sigLB: forgedSig });
    expect(ed25519.verify(forgedSig, contractSigMsg(ROOT, WALLET, 'LA'), hexToBytes(identity.slice(2)))).toBe(true);
    expect(verifySignedContract(terms, built.memoHex, built.uriHex)).toEqual({ ok: false, code: 'SIG_LA_INVALID' });
  });
});

describe('signContract', () => {
  it('refuses a signature that does not verify under the lawyer key (a broken FROST aggregate)', async () => {
    const terms: ContractTerms = {
      contractRoot: ROOT,
      walletAddress: WALLET,
      lawyerPubA: edPub(SEED_LA),
      lawyerPubB: edPub(SEED_LB),
    };
    await expect(signContract(signer(SEED_LB), terms, 'LA')).rejects.toThrow(/does not verify/);
  });
});

describe('T-U-15 mint memo', () => {
  const sample = (): MintMemo => ({
    lawyerPubA: edPub(SEED_LA),
    sigLA: new Uint8Array(64).fill(0x31),
    lawyerPubB: edPub(SEED_LB),
    sigLB: new Uint8Array(64).fill(0x32),
  });

  it('T-U-15a decodeMintMemo(encodeMintMemo(x)) equals x', () => {
    const x = sample();
    expect(decodeMintMemo(encodeMintMemo(x))).toEqual({ ok: true, value: x });
  });

  it('T-U-15b the memo is exactly 195 bytes and the serialized Memos field is under 1024 bytes', () => {
    const memoHex = encodeMintMemo(sample());
    expect(memoHex.length / 2).toBe(195);
    const memos = xrpl.encode({ Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: memoHex } }] } as never);
    expect(memos.length / 2).toBeLessThan(1024);
    // Memos F9, Memo EA, MemoType 7C + 1 length byte + 21, MemoData 7D + 2 length bytes + 195, end markers E1 F1.
    expect(memos.length / 2).toBe(225);
  });

  it('P1.5-01 a wrong version byte or a length other than 195 is an error result', () => {
    const memoHex = encodeMintMemo(sample());
    const bad = [
      `02${memoHex.slice(2)}`,
      `00${memoHex.slice(2)}`,
      memoHex.slice(0, -2),
      `${memoHex}00`,
      '',
      memoHex.toLowerCase(),
      `01${'00'.repeat(194)}`, // keys without the ED prefix
      'ZZ'.repeat(195),
    ];
    for (const b of bad) expect(decodeMintMemo(b)).toEqual({ ok: false, code: 'MEMO_MALFORMED' });
  });

  it('property: round trip for random keys and signatures', () => {
    const b = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
    fc.assert(
      fc.property(b(32), b(64), b(32), b(64), (ka, sa, kb, sb) => {
        const x = { lawyerPubA: `ED${up(ka)}`, sigLA: sa, lawyerPubB: `ED${up(kb)}`, sigLB: sb };
        expect(decodeMintMemo(encodeMintMemo(x))).toEqual({ ok: true, value: x });
      }),
    );
  });
});

describe('P1.5-02 URI checks', () => {
  it('a wrong prefix or lower-case hex fails with URI_MALFORMED', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    const sealHex = up(d.seal);
    const uri = (s: string) => up(utf8(s));
    const bad = [
      uri(`legx:sc:v2:${sealHex}`),
      uri(`LEGX:SC:V1:${sealHex}`),
      uri(`legx:sc:v1:${sealHex.toLowerCase()}`),
      uri(`legx:sc:v1:${sealHex}00`),
      uri(`legx:sc:v1:${sealHex}`).toLowerCase(),
      uri(` legx:sc:v1:${sealHex}`),
      '',
      'XYZ',
    ];
    for (const u of bad)
      expect(verifySignedContract(d.terms, d.memoHex, u)).toEqual({ ok: false, code: 'URI_MALFORMED' });
  });

  it('the URI is 75 bytes, under the 256-byte NFTokenMint limit', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    expect(d.uriHex.length / 2).toBe(75);
  });
});

describe('P1.5-03 golden vector and the Python cross-check', () => {
  it('fixed keys and root give the committed seal, URI and memo', async () => {
    const d = await makeDeal(SEED_LA, SEED_LB, ROOT, WALLET);
    // Values computed by tools/py-ref (legx_ref.py, written from DESIGN alone) from these keys and signatures;
    // the Ed25519 signatures themselves were checked with Node crypto (OpenSSL). See build/status/1.4-1.7.md.
    expect(d.terms.lawyerPubA).toBe(GOLDEN.lawyerPubA);
    expect(d.terms.lawyerPubB).toBe(GOLDEN.lawyerPubB);
    expect(up(d.sigLA)).toBe(GOLDEN.sigLA);
    expect(up(d.sigLB)).toBe(GOLDEN.sigLB);
    expect(bytesToHex(d.seal)).toBe(GOLDEN.seal);
    expect(d.uriHex).toBe(GOLDEN.uri);
    expect(d.memoHex).toBe(GOLDEN.memo);
  });

  it('matches tools/py-ref/vectors/signed_contract.json', () => {
    const msg = pyVector('signed_contract', 'contractSigMsg');
    const root = hexToBytes(msg.inputs.root as string);
    expect(bytesToHex(contractSigMsg(root, msg.inputs.wallet as string, 'LA'))).toBe(msg.output);

    const sv = pyVector('signed_contract', 'signedContractSeal');
    const terms: ContractTerms = {
      contractRoot: hexToBytes(sv.inputs.root as string),
      walletAddress: sv.inputs.wallet as string,
      lawyerPubA: sv.inputs.pubA as string,
      lawyerPubB: sv.inputs.pubB as string,
    };
    const built = buildSignedContractSeal(terms, {
      sigLA: hexToBytes(sv.inputs.sigLA as string),
      sigLB: hexToBytes(sv.inputs.sigLB as string),
    });
    expect(bytesToHex(built.seal)).toBe(sv.output);

    const uv = pyVector('signed_contract', 'nftUri');
    expect(nftUri(hexToBytes(uv.inputs.seal as string))).toBe(uv.output);
    expect(built.uriHex).toBe(uv.output);

    const mv = pyVector<Record<string, string>, { MemoType: string; MemoData: string }>('signed_contract', 'mintMemo');
    expect(MINT_MEMO_TYPE).toBe(mv.output.MemoType);
    expect(built.memoHex).toBe(mv.output.MemoData);
  });
});

describe('property: round trip and single-field mutations', () => {
  it('random roots, wallets and lawyer keys verify; a mutated root, wallet or signature fails', async () => {
    const b = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
    await fc.assert(
      fc.asyncProperty(b(32), b(32), b(32), b(32), fc.nat(), async (root, sa, sb, acct, i) => {
        fc.pre(bytesToHex(sa) !== bytesToHex(sb));
        const wallet = xrpl.encodeAccountID(acct.subarray(0, 20));
        const d = await makeDeal(sa, sb, root, wallet);
        expect(verifySignedContract(d.terms, d.memoHex, d.uriHex)).toEqual({ ok: true });
        expect(verifySignedContract({ ...d.terms, contractRoot: flipByte(root, i) }, d.memoHex, d.uriHex).ok).toBe(
          false,
        );
        const otherWallet = xrpl.encodeAccountID(flipByte(acct.subarray(0, 20), i));
        expect(verifySignedContract({ ...d.terms, walletAddress: otherWallet }, d.memoHex, d.uriHex).ok).toBe(false);
        const memo = hexToBytes(d.memoHex);
        expect(verifySignedContract(d.terms, up(flipByte(memo, 1 + (i % 194))), d.uriHex).ok).toBe(false);
      }),
      { numRuns: 30 },
    );
  });
});

const GOLDEN = {
  lawyerPubA: 'EDBC7CBCB5636375FA1D82434D466724D92377F53B980695DD49D26D0CE12205A5',
  lawyerPubB: 'ED55154F42065EA5A1BEA05463826BE2684EB92DF92C100027AABAAE57CA554207',
  sigLA:
    '362C5177B883F9C21A8EE24C8B34C8D95E2D39E9F134974B7E1430655788F1B59100C18370EA241490A42FD820A927736409B7988FE6BE7C2EC450AA028BEB07',
  sigLB:
    '1F7BDC7820C74B38B998F1EE7E8EFBBC515BA2B6F148DF3327CC4F2126D5BAA65620C8809158EEAFA3B24EAABDAF6593CFAF55D0A18518E9C58A3DAF9E78EA08',
  seal: '03fa0a0010782f41dde2cd0a3c0abb6c650dc5657ebedf7eadc203568412177c',
  uri: '6C6567783A73633A76313A30334641304130303130373832463431444445324344304133433041424236433635304443353635374542454446374541444332303335363834313231373743',
  memo: '01EDBC7CBCB5636375FA1D82434D466724D92377F53B980695DD49D26D0CE12205A5362C5177B883F9C21A8EE24C8B34C8D95E2D39E9F134974B7E1430655788F1B59100C18370EA241490A42FD820A927736409B7988FE6BE7C2EC450AA028BEB07ED55154F42065EA5A1BEA05463826BE2684EB92DF92C100027AABAAE57CA5542071F7BDC7820C74B38B998F1EE7E8EFBBC515BA2B6F148DF3327CC4F2126D5BAA65620C8809158EEAFA3B24EAABDAF6593CFAF55D0A18518E9C58A3DAF9E78EA08',
};
