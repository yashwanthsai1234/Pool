// FileSigner: both private keys in one local file. DEMO ONLY: it refuses to start unless LEGX_PROFILE=demo
// (P3.6-02), so a demo key file can never sign in production.

import { createPrivateKey, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { CheckpointSignerPort, SignerPort } from '@legx/contracts/ports';
import { KeyId } from '@legx/contracts/values';
import { z } from 'zod';
import {
  generateNodeCheckpointKeys,
  generateNodeSignerKeys,
  type NodeCheckpointKeys,
  type NodeSignerKeys,
  nodeCheckpointSigner,
  nodeSigner,
} from './node.ts';
import { assertDemoProfile } from './profile.ts';

type Env = Readonly<Record<string, string | undefined>>;

const Entry = z.object({ keyId: KeyId, pkcs8Pem: z.string() }).strict();
const SignerFile = z.object({ ed25519: Entry, mlDsa65: Entry }).strict();
const CheckpointFile = z.object({ ed25519: Entry, mlDsa44: Entry }).strict();

const pem = (key: KeyObject) => key.export({ format: 'pem', type: 'pkcs8' }).toString();
const load = (e: z.infer<typeof Entry>) => ({ keyId: e.keyId, privateKey: createPrivateKey(e.pkcs8Pem) });
const save = (path: string, body: unknown) =>
  writeFileSync(path, JSON.stringify(body, null, 2), { mode: 0o600, flag: 'wx' });
const entry = (k: { keyId: KeyId; privateKey: KeyObject }) => ({ keyId: k.keyId, pkcs8Pem: pem(k.privateKey) });

/** Opens the key file at `path`, creating fresh demo keys (mode 0600) on first start. */
export function fileSigner(path: string, env: Env = process.env): SignerPort {
  assertDemoProfile('FileSigner', env);
  if (!existsSync(path)) {
    const k = generateNodeSignerKeys(KeyId.parse('demo-ed25519-1'), KeyId.parse('demo-mldsa65-1'));
    save(path, { ed25519: entry(k.ed25519), mlDsa65: entry(k.mlDsa65) });
  }
  const f = SignerFile.parse(JSON.parse(readFileSync(path, 'utf8')));
  const keys: NodeSignerKeys = { ed25519: load(f.ed25519), mlDsa65: load(f.mlDsa65) };
  return nodeSigner(keys);
}

/** The demo checkpoint signer (Ed25519 and ML-DSA-44) from a key file; same demo-only rule. */
export function fileCheckpointSigner(path: string, env: Env = process.env): CheckpointSignerPort {
  assertDemoProfile('FileCheckpointSigner', env);
  if (!existsSync(path)) {
    const k = generateNodeCheckpointKeys(KeyId.parse('demo-log-ed25519-1'), KeyId.parse('demo-log-mldsa44-1'));
    save(path, { ed25519: entry(k.ed25519), mlDsa44: entry(k.mlDsa44) });
  }
  const f = CheckpointFile.parse(JSON.parse(readFileSync(path, 'utf8')));
  const keys: NodeCheckpointKeys = { ed25519: load(f.ed25519), mlDsa44: load(f.mlDsa44) };
  return nodeCheckpointSigner(keys);
}

/**
 * The production checkpoint signer from a key file that the deployment mounts as a secret (read only: it never creates
 * keys). Both halves are required, and the file must be readable by this process only. Same file format as the demo.
 */
export function secretCheckpointSigner(path: string): CheckpointSignerPort {
  const f = CheckpointFile.parse(JSON.parse(readFileSync(path, 'utf8')));
  return nodeCheckpointSigner({ ed25519: load(f.ed25519), mlDsa44: load(f.mlDsa44) });
}
