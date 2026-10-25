// The offline verifier that goes inside every evidence bundle as `assets/verify.ts` (DESIGN 8.8 item 12): the CLI of
// tools/verifier-cli bundled into one file that runs on a bare Node 24. Built once, at start-up.
// Source: https://esbuild.github.io/api/#build (tools/verifier-cli/scripts/bundle.ts)
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bundleCli } from '../../../tools/verifier-cli/scripts/bundle.ts';

export async function verifyScriptText(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'legx-verify-js-'));
  try {
    const out = join(dir, 'verify.js');
    await bundleCli(out);
    return await readFile(out, 'utf8');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
