// The share-2 backup file: versioned JSON holding only public slot data and share-2 ciphertext (under the PRF key
// or the recovery-code key) with the identity salt. The file alone opens nothing. Parsed strictly: any unknown
// field, wrong length or bad hex is `FILE_INVALID`.
import type { SlotPublic } from '@legx/core/frost';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { z } from 'zod';
import type { Sealed } from './aead.ts';
import { VaultError } from './errors.ts';
import type { PrfCredential } from './prf.ts';
import type { Share2Mode } from './rules.ts';

export type FileLock =
  | { kind: 'prf'; credential: PrfCredential; prfInput: Uint8Array }
  | { kind: 'code'; kdfSalt: Uint8Array; iterations: number };
type BackupFile = {
  id: string;
  mode: Share2Mode;
  pub: SlotPublic;
  identifier: string;
  lock: FileLock;
  share: Sealed;
  salt?: Sealed | undefined;
};

const hex = (min: number, max = min) =>
  z
    .string()
    .regex(new RegExp(`^(?:[0-9a-f]{2}){${min},${max}}$`))
    .transform((h) => hexToBytes(h));
const sealed = z.strictObject({ iv: hex(12), ct: hex(48) }); // 32-byte value + 16-byte tag
const Schema = z.strictObject({
  v: z.literal(1),
  kind: z.literal('legx-vault-share2'),
  id: z.string().max(80),
  mode: z.enum(['security-key', 'single-device', 'recovery-code']),
  pub: z.strictObject({
    min: z.literal(2),
    max: z.literal(3),
    commitments: z.array(hex(32)).length(2),
    verifyingShares: z.record(z.string().regex(/^[0-9a-f]{64}$/), hex(32)),
  }),
  identifier: z.string().regex(/^[0-9a-f]{64}$/),
  lock: z.discriminatedUnion('kind', [
    z.strictObject({
      kind: z.literal('prf'),
      credential: z.strictObject({
        id: z.string().regex(/^[A-Za-z0-9_-]{1,1366}$/),
        transports: z.array(z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'])).max(7),
      }),
      prfInput: hex(32),
    }),
    z.strictObject({ kind: z.literal('code'), kdfSalt: hex(16), iterations: z.int() }),
  ]),
  share: sealed,
  salt: sealed.optional(),
});

const sealedHex = (s: Sealed) => ({ iv: bytesToHex(s.iv), ct: bytesToHex(s.ct) });

export function encodeFile(f: BackupFile): Uint8Array {
  const lock =
    f.lock.kind === 'prf'
      ? { kind: 'prf', credential: f.lock.credential, prfInput: bytesToHex(f.lock.prfInput) }
      : { kind: 'code', kdfSalt: bytesToHex(f.lock.kdfSalt), iterations: f.lock.iterations };
  const json = {
    v: 1,
    kind: 'legx-vault-share2',
    id: f.id,
    mode: f.mode,
    pub: {
      min: f.pub.signers.min,
      max: f.pub.signers.max,
      commitments: f.pub.commitments.map(bytesToHex),
      verifyingShares: Object.fromEntries(Object.entries(f.pub.verifyingShares).map(([k, v]) => [k, bytesToHex(v)])),
    },
    identifier: f.identifier,
    lock,
    share: sealedHex(f.share),
    ...(f.salt ? { salt: sealedHex(f.salt) } : {}),
  };
  return new TextEncoder().encode(JSON.stringify(json));
}

export function decodeFile(bytes: Uint8Array): BackupFile {
  let parsed: z.infer<typeof Schema>;
  try {
    parsed = Schema.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  } catch {
    throw new VaultError('FILE_INVALID');
  }
  const { pub, ...rest } = parsed;
  return {
    ...rest,
    pub: {
      signers: { min: pub.min, max: pub.max },
      commitments: pub.commitments,
      verifyingShares: pub.verifyingShares,
    },
  };
}
