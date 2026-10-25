import { execFileSync, spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as pkijs from 'pkijs';

pkijs.setEngine(
  'node',
  new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }) as unknown as pkijs.ICryptoEngine,
);

export { pkijs };

export const certOf = (der: Uint8Array) => pkijs.Certificate.fromBER(der);

/** keyUsage bits as named by RFC 5280 4.2.1.3, read with PKI.js (an implementation independent of the builder). */
export function keyUsageOf(der: Uint8Array): string[] {
  const ext = certOf(der).extensions?.find((e) => e.extnID === '2.5.29.15');
  if (!ext) return [];
  const bits = new Uint8Array(
    (ext.parsedValue as { valueBlock: { valueHexView: Uint8Array } }).valueBlock.valueHexView,
  );
  const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement'];
  names.push('keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly');
  return names.filter((_, i) => ((bits[i >> 3] ?? 0) >> (7 - (i & 7))) & 1);
}

export const pem = (der: Uint8Array, label = 'CERTIFICATE') =>
  `-----BEGIN ${label}-----\n${(
    Buffer.from(der)
      .toString('base64')
      .match(/.{1,64}/g) ?? []
  ).join('\n')}\n-----END ${label}-----\n`;

/** OpenSSL 3 from Homebrew if present, else the one on the PATH, else none (the OpenSSL tests are then skipped). */
export const OPENSSL = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/bin/openssl'].find((p) => {
  if (!existsSync(p)) return false;
  return execFileSync(p, ['version']).toString().startsWith('OpenSSL 3');
});

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'legx-fixtures-'));
}

export function writeFiles(dir: string, files: Record<string, string | Uint8Array>): void {
  for (const [name, data] of Object.entries(files)) writeFileSync(join(dir, name), data);
}

/** Runs OpenSSL and returns its exit status and combined stdout and stderr; never throws on a non-zero exit. */
export function openssl(args: string[], cwd: string): { ok: boolean; out: string } {
  const r = spawnSync(OPENSSL ?? 'openssl', args, { cwd });
  return { ok: r.status === 0, out: `${r.stdout?.toString() ?? ''}${r.stderr?.toString() ?? ''}` };
}
