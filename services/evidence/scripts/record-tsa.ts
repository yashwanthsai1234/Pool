// Records one real RFC 3161 exchange per authority into test/fixtures/tsa/ (run by hand: `node scripts/record-tsa.ts`).
// The default tests replay these bytes; the request is rebuilt from the fixed hash and nonce, so the replay stub can
// insist on byte-equality with the recorded request.
import { mkdirSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { DEFAULT_AUTHORITIES, SECTIGO, tsaClient } from '../src/tsa.ts';
import { FIXTURE_HASH, FIXTURE_NONCE } from '../test/helpers/tsaFixture.ts';

mkdirSync(new URL('../test/fixtures/tsa/', import.meta.url), { recursive: true });
for (const authority of [...DEFAULT_AUTHORITIES, SECTIGO]) {
  const exchange: { req?: Uint8Array; resp?: Uint8Array } = {};
  const recording: typeof fetch = async (url, init) => {
    exchange.req = new Uint8Array(init?.body as ArrayBuffer);
    const res = await fetch(url, init);
    exchange.resp = new Uint8Array(await res.clone().arrayBuffer());
    return res;
  };
  const { nodeRootCertificates } = await import('../src/tsa.ts');
  const client = tsaClient({
    authority,
    trustedRoots: nodeRootCertificates(),
    fetch: recording,
    nonce: () => FIXTURE_NONCE,
  });
  const hex = Buffer.from(FIXTURE_HASH).toString('hex') as never;
  await client.timestamp(hex);
  const dir = new URL(`../test/fixtures/tsa/${authority.name}.`, import.meta.url).pathname;
  writeFileSync(`${dir}req`, exchange.req as Uint8Array);
  writeFileSync(`${dir}resp`, exchange.resp as Uint8Array);
  process.stdout.write(
    `${authority.name}: ${exchange.resp?.length} bytes, sha256 ${Buffer.from(sha256(exchange.resp as Uint8Array)).toString('hex')}\n`,
  );
}
