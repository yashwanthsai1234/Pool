// Participants of the product demo (build/PRODUCT_DEMO.md 1): demo keys held by the server, a RID that fingerprints them,
// and an XRPL account funded on the standalone ledger.
// Source: build/PRODUCT_DEMO.md section 1
import { createHash, generateKeyPairSync, type KeyObject, sign } from 'node:crypto';
import { tupleHash } from '@legx/core/dealcore';
import { standaloneEnv } from '../../../../packages/xrpl/src/env.ts';
import { newWallet, openChain } from '../../../../packages/xrpl/test-int/roles.ts';

export type Wallet = ReturnType<typeof newWallet>;

export interface PublicParticipant {
  readonly rid: string;
  readonly name: string;
  readonly fingerprint: string;
  readonly xrplAddress: string;
}

export interface Participant extends PublicParticipant {
  readonly createdAt: string;
  readonly wallet: Wallet;
  readonly edKey: KeyObject;
}

// RFC 4648 base32, lower case, no padding. Source: https://www.rfc-editor.org/rfc/rfc4648#section-6
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
export function base32lower(b: Uint8Array): string {
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const x of b) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits > 0 ? out + B32[(acc << (5 - bits)) & 31] : out;
}

/** rid = "rid_" + base32lower(first 10 bytes of tupleHash("legx/rid/v1", [ed25519Pub, mldsa65Pub])). */
export function ridOf(ed25519Pub: Uint8Array, mldsa65Pub: Uint8Array): { rid: string; fingerprint: string } {
  const h = tupleHash('legx/rid/v1', [ed25519Pub, mldsa65Pub]);
  return { rid: `rid_${base32lower(h.subarray(0, 10))}`, fingerprint: Buffer.from(h).toString('hex') };
}

/** The first 16 hex of SHA-256 of the actor's Ed25519 signature over tupleHash("legx/demo-approve/v1", [dealId, stage, rid]). */
export function approvalFingerprint(p: Participant, dealId: string, stage: number, rid: string): string {
  const msg = tupleHash(
    'legx/demo-approve/v1',
    [dealId, String(stage), rid].map((s) => Buffer.from(s, 'utf8')),
  );
  return createHash('sha256')
    .update(sign(null, msg, p.edKey))
    .digest('hex')
    .slice(0, 16);
}

// The raw public key is the tail of its SPKI DER (Ed25519: 32 bytes; ML-DSA-65: 1952 bytes, FIPS 204 table 2).
// Source: https://www.rfc-editor.org/rfc/rfc8410 ; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
const raw = (k: KeyObject, n: number) => new Uint8Array(k.export({ format: 'der', type: 'spki' }).subarray(-n));

export class Participants {
  readonly #all = new Map<string, Participant>();
  readonly #ledgerWs: string;
  constructor(ledgerWs: string) {
    this.#ledgerWs = ledgerWs;
  }

  async register(name: string): Promise<Participant> {
    const ed = generateKeyPairSync('ed25519');
    const pq = generateKeyPairSync('ml-dsa-65');
    const { rid, fingerprint } = ridOf(raw(ed.publicKey, 32), raw(pq.publicKey, 1952));
    const wallet = newWallet('ed25519');
    const c = await openChain(standaloneEnv(this.#ledgerWs));
    try {
      await c.fund(wallet, 1000);
    } finally {
      await c.close();
    }
    const p = {
      rid,
      name,
      fingerprint,
      xrplAddress: wallet.classicAddress,
      createdAt: new Date().toISOString(),
      wallet,
      edKey: ed.privateKey,
    };
    this.#all.set(rid, p);
    return p;
  }

  get(rid: string): Participant | undefined {
    return this.#all.get(rid);
  }

  list(): PublicParticipant[] {
    return [...this.#all.values()].map(pub);
  }
}

export const pub = (p: Participant): PublicParticipant => ({
  rid: p.rid,
  name: p.name,
  fingerprint: p.fingerprint,
  xrplAddress: p.xrplAddress,
});
