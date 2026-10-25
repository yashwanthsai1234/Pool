// `release.json`: the signed statement of which bundle is the release (DESIGN 6.4 "Code integrity").
// The body names the version, the lowest version still allowed (rollback), the app origin that may embed the vault,
// and the hash of every file. It is signed with the release key, Ed25519 plus ML-DSA-65 (DESIGN 6.13), over a
// canonical text with its own context, so the signature cannot be replayed as any other signed message.
// Browser-safe: the vault frame verifies it with the release public keys baked into the bundle.
// Source: https://csrc.nist.gov/pubs/fips/204/final (ML-DSA context string)
import type { HybridSignature, MlDsaContext, SignerPort } from '@legx/contracts/ports';
import { mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { z } from 'zod';
import { type FileHashes, manifestHash } from './manifest.ts';

export const RELEASE_CONTEXT = 'legx/release/v1';
// The contracts type lists the three existing contexts only. A request for 'legx/release/v1' is in build/status/4.10.md.
const CONTEXT = RELEASE_CONTEXT as MlDsaContext;

const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const version = z.string().regex(/^\d{1,6}\.\d{1,6}\.\d{1,6}$/);
const b64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/);

export const ReleaseBody = z.strictObject({
  schema: z.literal(RELEASE_CONTEXT),
  version,
  minVersion: version,
  appOrigin: z.string().regex(/^https?:\/\/[^/?#]+$/),
  files: z.record(z.string().regex(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/), hex64),
  manifestHash: hex64,
});
export type ReleaseBody = z.infer<typeof ReleaseBody>;

export const Release = z.strictObject({ body: ReleaseBody, ed25519: b64, mlDsa65: b64 });
export type Release = z.infer<typeof Release>;

export type ReleaseCode = 'FORMAT' | 'MANIFEST' | 'SIGNATURE' | 'VERSION';
export class ReleaseError extends Error {
  readonly code: ReleaseCode;
  constructor(code: ReleaseCode) {
    super(`release.json refused: ${code}`);
    this.name = 'ReleaseError';
    this.code = code;
  }
}

/** The exact bytes that are signed: fixed key order, sorted files, no whitespace. */
export function releaseMessage(body: ReleaseBody): Uint8Array {
  const files = Object.fromEntries(
    Object.keys(body.files)
      .sort()
      .map((p) => [p, body.files[p]]),
  );
  const { schema, version: v, minVersion, appOrigin, manifestHash: m } = body;
  return utf8ToBytes(
    `${RELEASE_CONTEXT}\n${JSON.stringify({ schema, version: v, minVersion, appOrigin, files, manifestHash: m })}`,
  );
}

const toB64 = (b: Uint8Array): string => {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
};
const fromB64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function compareVersions(a: string, b: string): number {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return (x[i] as number) - (y[i] as number);
  return 0;
}

/** Signs a release body with the release key (a `NodeSigner` from `@legx/signer`, or any hybrid `SignerPort`). */
export async function signRelease(signer: SignerPort, body: ReleaseBody): Promise<Release> {
  const sig: HybridSignature = await signer.signHybrid(releaseMessage(body), CONTEXT);
  return { body, ed25519: toB64(sig.ed25519), mlDsa65: toB64(sig.mlDsa65) };
}

/** Both signatures must verify, the manifest hash must match the file list, and `minVersion` may not exceed `version`. */
export function verifyRelease(input: unknown, keys: { ed25519: Uint8Array; mlDsa65: Uint8Array }): ReleaseBody {
  const parsed = Release.safeParse(input);
  if (!parsed.success) throw new ReleaseError('FORMAT');
  const { body } = parsed.data;
  if (manifestHash(body.files as FileHashes) !== body.manifestHash) throw new ReleaseError('MANIFEST');
  if (compareVersions(body.minVersion, body.version) > 0) throw new ReleaseError('VERSION');
  const msg = releaseMessage(body);
  let edOk = false;
  try {
    edOk = ed25519.verify(fromB64(parsed.data.ed25519), msg, keys.ed25519);
  } catch {
    edOk = false;
  }
  if (!edOk || !mldsaVerify('ml-dsa-65', keys.mlDsa65, msg, fromB64(parsed.data.mlDsa65), CONTEXT as never)) {
    throw new ReleaseError('SIGNATURE');
  }
  return body;
}
