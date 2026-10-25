// ERR_REQUIRE_CYCLE_MODULE check (task 1.3): xrpl 5.3.0 is CommonJS and require()s noble 2.x (ESM).
// Seen on Node 22.14.0 when a file imports xrpl before noble. Not seen on Node 24.22.1 (evidence in build/status/1.3.md).
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';

const core = join(dirname(fileURLToPath(import.meta.url)), '..');

it.each([
  ['xrpl first', "import { Wallet } from 'xrpl';\nimport { ed25519 } from '@noble/curves/ed25519.js';"],
  ['noble first', "import { ed25519 } from '@noble/curves/ed25519.js';\nimport { Wallet } from 'xrpl';"],
])('plain Node loads xrpl and noble as static imports (%s)', (_name, imports) => {
  // The probe lives inside packages/core so Node resolves the packages from its node_modules.
  const dir = mkdtempSync(join(core, '.cycle-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, `${imports}\nprocess.stdout.write(typeof Wallet + typeof ed25519.verify);\n`);
  try {
    expect(execFileSync(process.execPath, [file], { encoding: 'utf8' })).toBe('functionfunction');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
