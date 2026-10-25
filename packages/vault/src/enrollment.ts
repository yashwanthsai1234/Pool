// Enrollment keys (DESIGN 6.3): one per share holder per deal, made on this device. The Ed25519 half is a WebCrypto
// key with a non-extractable private key, stored in IndexedDB. The ML-DSA-65 half belongs to task 4.9; it plugs in
// through `PqHalf` (for example over `mldsaSign` from `@legx/core/pq`), and `hybridSigner` joins both into the
// contracts `SignerPort`, so neither half is ever returned alone.
// Source: https://w3c.github.io/webcrypto/#ed25519 (Chrome 137+, Firefox 129+, Safari 17+)
import type { MlDsaContext, SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { DealId } from '@legx/contracts/values';
import { bs } from './aead.ts';
import { VaultError } from './errors.ts';
import type { PartyRole } from './rules.ts';
import { Store } from './store.ts';

/** The ML-DSA-65 half, supplied by task 4.9. */
export interface PqHalf {
  readonly keyId: KeyId;
  readonly publicKey: Uint8Array; // 1,952 bytes
  sign(msg: Uint8Array, ctx: MlDsaContext): Promise<Uint8Array>;
}

type Row = { id: string; role: PartyRole; privateKey: CryptoKey; publicKey: Uint8Array };

export function enrollmentKeys(opts: { role: PartyRole; dbName?: string }) {
  const store = new Store(opts.dbName ?? 'legx-vault');
  const idOf = (dealId: string) => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${opts.role}:enrollment`;
  };
  const row = async (dealId: string) => {
    const r = await store.get<Row>('enrollment', idOf(dealId));
    if (!r) throw new VaultError('NOT_FOUND');
    return r;
  };
  const sign = async (dealId: string, msg: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign('Ed25519', (await row(dealId)).privateKey, bs(msg)));

  return {
    /** Makes the key once; later calls return the same public key (32 raw bytes). */
    async create(dealId: string): Promise<Uint8Array> {
      const id = idOf(dealId);
      const have = await store.get<Row>('enrollment', id);
      if (have) return have.publicKey;
      const kp = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
      const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
      await store.put('enrollment', { id, role: opts.role, privateKey: kp.privateKey, publicKey });
      return publicKey;
    },

    /** An Ed25519 signature (64 bytes) for the DKG messages that run inside the frame (task 4.7). */
    sign,

    /** The hybrid signer: Ed25519 from this store, ML-DSA-65 from task 4.9. */
    async hybridSigner(dealId: string, edKeyId: KeyId, pq: PqHalf): Promise<SignerPort> {
      const { publicKey } = await row(dealId);
      const keyIds = { ed25519: edKeyId, mlDsa65: pq.keyId };
      return {
        async signHybrid(msg, ctx) {
          const [ed25519, mlDsa65] = await Promise.all([sign(dealId, msg), pq.sign(msg, ctx)]);
          return { ed25519, mlDsa65, keyIds };
        },
        publicKeys: async () => ({ ed25519: publicKey, mlDsa65: pq.publicKey, keyIds }),
      };
    },
  };
}
