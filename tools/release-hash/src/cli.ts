#!/usr/bin/env node
// release-hash keygen --out <dir>
// release-hash sign --dir <build dir> --version x.y.z --min-version x.y.z --app-origin <origin> --keys <dir>
// `keygen` writes the release keys as PEM files and the public keys as hex (`public.json`, what the build bakes in).
// `sign` hashes the build directory and writes `release.json`, signed through the `NodeSigner` of @legx/signer.
import { createPrivateKey } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { KeyId } from '@legx/contracts/values';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { bytesToHex } from '@noble/hashes/utils.js';
import { writeRelease } from './build.ts';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    out: { type: 'string' },
    dir: { type: 'string' },
    keys: { type: 'string' },
    version: { type: 'string' },
    'min-version': { type: 'string' },
    'app-origin': { type: 'string' },
  },
});
const need = (v: string | undefined, name: string): string => {
  if (!v) throw new Error(`missing --${name}`);
  return v;
};
const ids = [KeyId.parse('release-ed25519'), KeyId.parse('release-ml-dsa-65')] as const;

if (positionals[0] === 'keygen') {
  const out = need(values.out, 'out');
  const keys = generateNodeSignerKeys(...ids);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'ed25519.pem'), keys.ed25519.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
    mode: 0o600,
  });
  writeFileSync(join(out, 'ml-dsa-65.pem'), keys.mlDsa65.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
    mode: 0o600,
  });
  const pub = await nodeSigner(keys).publicKeys();
  writeFileSync(
    join(out, 'public.json'),
    JSON.stringify({ ed25519: bytesToHex(pub.ed25519), mlDsa65: bytesToHex(pub.mlDsa65) }),
  );
} else if (positionals[0] === 'sign') {
  const dir = need(values.keys, 'keys');
  const load = (f: string) => createPrivateKey(readFileSync(join(dir, f)));
  const signer = nodeSigner({
    ed25519: { keyId: ids[0], privateKey: load('ed25519.pem') },
    mlDsa65: { keyId: ids[1], privateKey: load('ml-dsa-65.pem') },
  });
  const version = need(values.version, 'version');
  const release = await writeRelease({
    dir: need(values.dir, 'dir'),
    version,
    minVersion: values['min-version'] ?? version,
    appOrigin: need(values['app-origin'], 'app-origin'),
    signer,
  });
  process.stdout.write(`${release.body.manifestHash}\n`);
} else {
  throw new Error('usage: release-hash keygen|sign (see the header of cli.ts)');
}
