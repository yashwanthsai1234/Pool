// DESIGN 8.8 item 1: manifest.json lists the SHA-256 of every file, and manifest.dsse.json is the service's hybrid
// signature over a subject digest of the manifest. Any changed byte in any file fails here, naming the file.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (PAE, multiple signatures)
import { type Envelope, pae } from '@legx/core/evidence';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { type BundleFiles, b64, isObj } from './files.ts';
import type { Findings } from './report.ts';

export const MANIFEST_TYPE = 'application/vnd.legx.manifest+json;v=1';
const SELF = new Set(['manifest.json', 'manifest.dsse.json']);

export interface Manifest {
  readonly dealId: string | undefined;
}

export function checkManifest(files: BundleFiles, out: Findings): Manifest {
  const raw = files.json('manifest.json');
  if (!isObj(raw) || !Array.isArray(raw.files)) {
    out.fail('manifest', 'manifest.json', 'missing or not a manifest');
    return { dealId: undefined };
  }
  const listed = new Set<string>();
  for (const f of raw.files) {
    const path = isObj(f) ? f.path : undefined;
    if (!isObj(f) || typeof path !== 'string' || typeof f.sha256 !== 'string' || typeof f.size !== 'number') {
      out.fail('manifest', 'manifest.json', 'a manifest entry is malformed');
      continue;
    }
    if (listed.has(path) || SELF.has(path)) {
      out.fail('manifest', path, 'listed twice or lists itself');
      continue;
    }
    listed.add(path);
    const bytes = files.bytes(path);
    if (!bytes) out.fail('manifest', path, 'listed in the manifest but missing from the bundle');
    else if (bytes.length !== f.size)
      out.fail('manifest', path, `size ${bytes.length} differs from the manifest (${f.size})`);
    else if (bytesToHex(sha256(bytes)) !== f.sha256) out.fail('manifest', path, 'SHA-256 differs from the manifest');
    else out.pass('manifest', path, 'SHA-256 matches the manifest');
  }
  for (const p of files.paths)
    if (!listed.has(p) && !SELF.has(p)) out.fail('manifest', p, 'in the bundle but not in the manifest');
  return { dealId: typeof raw.deal_id === 'string' ? raw.deal_id : undefined };
}

export interface ServiceKeys {
  readonly ed: { readonly keyId: string; readonly publicKey: Uint8Array };
  readonly pq: { readonly keyId: string; readonly publicKey: Uint8Array };
}

export function readServiceKeys(files: BundleFiles): ServiceKeys | undefined {
  const k = files.json('keys/service_keys.json');
  if (!isObj(k) || !isObj(k.ed25519) || !isObj(k['ml-dsa-65'])) return undefined;
  const ed = k.ed25519;
  const pq = k['ml-dsa-65'];
  const edPub =
    typeof ed.public_key === 'string' && /^[0-9a-f]{64}$/.test(ed.public_key) ? hexToBytes(ed.public_key) : undefined;
  const pqPub = b64(pq.public_key);
  if (!edPub || !pqPub || typeof ed.key_id !== 'string' || typeof pq.key_id !== 'string') return undefined;
  return { ed: { keyId: ed.key_id, publicKey: edPub }, pq: { keyId: pq.key_id, publicKey: pqPub } };
}

/** The manifest envelope: subject digest, both signatures, in order. `pinned` is an Ed25519 key the arbitrator trusts. */
export function checkManifestSignature(
  files: BundleFiles,
  service: ServiceKeys | undefined,
  pinned: string | undefined,
  insecureUnpinned: boolean,
  out: Findings,
): undefined {
  const FILE = 'manifest.dsse.json';
  const fail = (m: string) => out.fail('manifest-signature', FILE, m);
  const env = files.json(FILE) as Envelope | undefined;
  const manifest = files.bytes('manifest.json');
  if (!isObj(env) || !manifest) return fail('missing or not a DSSE envelope');
  if (env.payloadType !== MANIFEST_TYPE || typeof env.payload !== 'string' || !Array.isArray(env.signatures))
    return fail('not a manifest envelope');
  const body = fromBase64Strict(env.payload);
  if (!body) return fail('payload is not canonical base64');
  let statement: unknown;
  try {
    statement = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return fail('payload is not JSON');
  }
  const subject = isObj(statement) && Array.isArray(statement.subject) ? statement.subject[0] : undefined;
  const digest = isObj(subject) && isObj(subject.digest) ? subject.digest.sha256 : undefined;
  if (digest !== bytesToHex(sha256(manifest)))
    return out.fail(
      'manifest-signature',
      'manifest.json',
      'the signed subject digest is not the SHA-256 of manifest.json',
    );
  if (!service) return fail('keys/service_keys.json is missing or malformed');
  const [s1, s2] = env.signatures;
  if (env.signatures.length !== 2 || !s1 || !s2)
    return fail('exactly two signatures are required (Ed25519 and ML-DSA-65)');
  if (s1.keyid !== service.ed.keyId || s2.keyid !== service.pq.keyId)
    return fail('signature key ids are not the service key ids');
  const msg = pae(MANIFEST_TYPE, body);
  const edSig = fromBase64Strict(s1.sig);
  const pqSig = fromBase64Strict(s2.sig);
  let edOk = false;
  try {
    edOk = !!edSig && ed25519.verify(edSig, msg, service.ed.publicKey, { zip215: false });
  } catch {
    edOk = false;
  }
  if (!edOk) return fail('Ed25519 signature is invalid');
  if (!pqSig || !mldsaVerify('ml-dsa-65', service.pq.publicKey, msg, pqSig, 'legx/dsse/v1'))
    return fail('ML-DSA-65 signature is invalid');
  const keyHex = bytesToHex(service.ed.publicKey);
  if (pinned === undefined && insecureUnpinned)
    out.warn('manifest-signature', FILE, `--insecure-unpinned: the signing key ${keyHex} is the one inside the bundle`);
  else if (pinned === undefined)
    out.fail(
      'manifest-signature',
      FILE,
      `the signing key ${keyHex} is not pinned: pass --service-key (or --insecure-unpinned for testing)`,
    );
  else if (pinned.toLowerCase() === keyHex)
    out.pass('manifest-signature', FILE, 'both signatures verify under the pinned service key');
  else out.fail('manifest-signature', FILE, `the signing key ${keyHex} is not the pinned key`);
}
