// Post-quantum enrollment keys held in the vault (DESIGN 6.3, 6.13; IMPLEMENTATION 4.9). Per deal and role, the vault
// keeps two 32-byte seeds and nothing else secret: the ML-DSA-65 seed (FIPS 204 ML-DSA.KeyGen_internal) and the
// X-Wing seed (draft-connolly-cfrg-xwing-kem, the decapsulation key is the seed). Both are sealed with AES-GCM under a
// fresh non-extractable device key, the scheme of share 1 (task 4.2). Every use decrypts the seed inside the call,
// expands the key, uses it once and zeroes every buffer it owns.
// noble post-quantum is not audited and not constant-time; it is used in the browser for enrollment and the binding only.
// Source: https://csrc.nist.gov/pubs/fips/204/final (ML-DSA-65, 32-byte seed xi, contexts)
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ (X-Wing, 32-byte decapsulation seed)
// Source: https://github.com/paulmillr/noble-post-quantum (0.7.1: keygen(seed), sign(msg, sk, { context }))
import type { MlDsaContext, SignerPort } from '@legx/contracts/ports';
import { DealId, type KeyId } from '@legx/contracts/values';
import { mldsaSign, openPackage, type SealedPackage } from '@legx/core/pq';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { aad, newDeviceKey, open, type Sealed, seal, wipe } from '../aead.ts';
import { enrollmentKeys, type PqHalf } from '../enrollment.ts';
import { VaultError } from '../errors.ts';
import type { PartyRole } from '../rules.ts';
import { Store } from '../store.ts';

/** The contexts a vault ML-DSA key signs under: the contracts set plus API requests (OD-5, DESIGN 8.10). */
export type PqContext = MlDsaContext | 'legx/api-request/v1';
/** The package kinds the vault opens with its X-Wing key for any role (the identity boxes have `openBox`, lawyers only). */
export type VaultPackageKind = 'share' | 'backup';
/** The identity boxes of a client's own lawyer (OD-32). */
export type ZkBoxKind = 'zk-salt' | 'zk-disclosure';

type Row = {
  id: string;
  role: PartyRole;
  key: CryptoKey;
  mlDsaSeed: Sealed;
  xwingSeed: Sealed;
  mlDsa65: Uint8Array;
  xwing: Uint8Array;
};
export type PqPublicKeys = { readonly mlDsa65: Uint8Array; readonly xwing: Uint8Array };

/** Key ids of a pair as the coordinator reads them (`<pair>#ed25519`, `<pair>#ml-dsa-65`). */
const pairKeyIds = (pairId: string) => ({
  ed25519: `${pairId}#ed25519` as KeyId,
  mlDsa65: `${pairId}#ml-dsa-65` as KeyId,
});

export function pqKeys(opts: { role: PartyRole; dbName?: string }) {
  const dbName = opts.dbName ?? 'legx-vault';
  const store = new Store(dbName);
  const idOf = (dealId: string) => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${opts.role}:pq`;
  };
  const row = async (dealId: string) => {
    const r = await store.get<Row>('enrollment', idOf(dealId));
    if (!r) throw new VaultError('NOT_FOUND');
    return r;
  };
  /** Opens one seed, hands it to `use`, and zeroes it whatever happens. */
  const withSeed = async <T>(dealId: string, field: 'mlDsaSeed' | 'xwingSeed', use: (seed: Uint8Array) => T) => {
    const r = await row(dealId);
    const seed = await open(r.key, r[field], aad(r.id, field));
    try {
      return await use(seed);
    } finally {
      wipe(seed);
    }
  };

  /** ML-DSA-65 signature; the expanded secret key lives only inside this call. */
  const signPq = (dealId: string, msg: Uint8Array, ctx: PqContext) =>
    withSeed(dealId, 'mlDsaSeed', (seed) => {
      const { secretKey } = ml_dsa65.keygen(seed);
      try {
        // Core's wrapper types its contexts as the contracts set; the API context is OD-5's (request in 4.9.md).
        return mldsaSign('ml-dsa-65', secretKey, msg, ctx as MlDsaContext);
      } finally {
        wipe(secretKey);
      }
    });

  const api = {
    /** Makes both seeds once; later calls return the same public keys. */
    async create(dealId: string): Promise<PqPublicKeys> {
      const id = idOf(dealId);
      const have = await store.get<Row>('enrollment', id);
      if (have) return { mlDsa65: have.mlDsa65, xwing: have.xwing };
      const mlSeed = crypto.getRandomValues(new Uint8Array(32));
      const xwSeed = crypto.getRandomValues(new Uint8Array(32));
      try {
        const expanded = ml_dsa65.keygen(mlSeed);
        wipe(expanded.secretKey);
        const key = await newDeviceKey();
        const r: Row = {
          id,
          role: opts.role,
          key,
          mlDsaSeed: await seal(key, mlSeed, aad(id, 'mlDsaSeed')),
          xwingSeed: await seal(key, xwSeed, aad(id, 'xwingSeed')),
          mlDsa65: expanded.publicKey,
          xwing: ml_kem768_x25519.getPublicKey(xwSeed),
        };
        await store.put('enrollment', r);
        return { mlDsa65: r.mlDsa65, xwing: r.xwing };
      } finally {
        wipe(mlSeed, xwSeed);
      }
    },

    async publicKeys(dealId: string): Promise<PqPublicKeys> {
      const r = await row(dealId);
      return { mlDsa65: r.mlDsa65, xwing: r.xwing };
    },

    /** The ML-DSA-65 half for task 4.2's `hybridSigner` and task 4.7's relay keys. */
    async half(
      dealId: string,
      keyId: string,
    ): Promise<PqHalf & { sign(msg: Uint8Array, ctx: PqContext): Promise<Uint8Array> }> {
      const { mlDsa65 } = await row(dealId);
      return { keyId: keyId as KeyId, publicKey: mlDsa65, sign: (msg, ctx) => signPq(dealId, msg, ctx) };
    },

    /** Opens a `zk-salt` or `zk-disclosure` box sealed to this vault's X-Wing key (OD-32: the client's own lawyer). */
    async openBox(dealId: string, kind: ZkBoxKind, pkg: SealedPackage, ad: Uint8Array): Promise<Uint8Array> {
      if (kind !== 'zk-salt' && kind !== 'zk-disclosure') throw new VaultError('INPUT_INVALID');
      const res = await withSeed(dealId, 'xwingSeed', (seed) => openPackage(kind, pkg, seed, ad));
      if (!res.ok) throw new VaultError('DECRYPT_FAILED');
      return res.plaintext;
    },

    /** The hybrid enrollment signer of a key pair (OD-5, OD-21, OD-31): Ed25519 (task 4.2) plus this ML-DSA-65 key. */
    async hybridSigner(dealId: string, pairId: string): Promise<SignerPort & { signRaw: HybridRaw }> {
      const ids = pairKeyIds(pairId);
      const half = await api.half(dealId, ids.mlDsa65);
      const ed = enrollmentKeys({ role: opts.role, dbName });
      await ed.create(dealId);
      const port = await ed.hybridSigner(dealId, ids.ed25519, half);
      const signRaw: HybridRaw = async (msg, ctx) => {
        const [ed25519, mlDsa65] = await Promise.all([ed.sign(dealId, msg), half.sign(msg, ctx)]);
        return { ed25519, mlDsa65, keyIds: ids };
      };
      return { ...port, signRaw };
    },

    /** Opens an X-Wing package of the share or backup kind sealed to this vault's key. */
    async open(dealId: string, kind: VaultPackageKind, pkg: SealedPackage, ad: Uint8Array): Promise<Uint8Array> {
      if (kind !== 'share' && kind !== 'backup') throw new VaultError('INPUT_INVALID');
      const res = await withSeed(dealId, 'xwingSeed', (seed) => openPackage(kind, pkg, seed, ad));
      if (!res.ok) throw new VaultError('DECRYPT_FAILED');
      return res.plaintext;
    },
  };
  return api;
}

/** A hybrid signature under any vault context, including the API-request one the contracts port does not list. */
export type HybridRaw = (
  msg: Uint8Array,
  ctx: PqContext,
) => Promise<{ ed25519: Uint8Array; mlDsa65: Uint8Array; keyIds: { ed25519: KeyId; mlDsa65: KeyId } }>;
