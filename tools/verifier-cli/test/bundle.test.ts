// DESIGN 8.8 item 12: the CLI and its dependencies in one file, runnable on a bare Node 24 with no node_modules.
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { bundleCli } from '../scripts/bundle.ts';
import { makeBundle } from './helpers.ts';
import { ready, withZk } from './zkHelpers.ts';

vi.setConfig({ testTimeout: 300_000, hookTimeout: 300_000 });

describe('one-file verify.js', () => {
  it('runs alone in an empty folder, with the network switched off, and exits 0; a changed bundle exits 1', async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'legx-onefile-')));
    const out = join(dir, 'verify.js');
    await bundleCli(out);
    expect(statSync(out).size).toBeGreaterThan(100_000);
    const code = readFileSync(out, 'utf8');
    // no HTTP, TLS, DNS or datagram module is part of the file (the xrpl client's `ws` is replaced by a stub). barretenberg
    // brings `net` for its Unix socket to the local prover program, and `child_process` to start it.
    expect(code).not.toMatch(/(?:from|require\()\s*["'](?:node:)?(?:http|https|http2|tls|dns|dgram)["']/);

    const b = await makeBundle();
    const zipPath = join(dir, 'bundle.zip');
    writeFileSync(zipPath, b.zip);
    // a bare folder: the script and the bundle only. Node's permission model also forbids child processes and workers.
    const bare = realpathSync(mkdtempSync(join(tmpdir(), 'legx-bare-')));
    copyFileSync(out, join(bare, 'verify.js'));
    const run = (zipFile: string) =>
      spawnSync(
        process.execPath,
        [
          '--permission',
          `--allow-fs-read=${bare}`,
          `--allow-fs-read=${dir}`,
          `--allow-fs-write=${bare}`,
          join(bare, 'verify.js'),
          zipFile,
          '--out-dir',
          bare,
          '--profile',
          'demo',
          '--insecure-unpinned',
          '--insecure-bundle-tsa-roots',
        ],
        {
          cwd: bare,
          encoding: 'utf8',
          env: { PATH: process.env.PATH ?? '' },
        },
      );
    const ok = run(zipPath);
    expect(ok.stderr).toBe('');
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain('RESULT: PASS');
    expect(JSON.parse(readFileSync(join(bare, 'legx-verify-report.json'), 'utf8')).result).toBe('pass');

    const bad = new Uint8Array(b.zip);
    bad[bad.length >> 1] = (bad[bad.length >> 1] as number) ^ 1;
    const badPath = join(dir, 'bad.zip');
    writeFileSync(badPath, bad);
    const failed = run(badPath);
    expect(failed.status).toBe(1);
    expect(failed.stdout).toContain('RESULT: FAIL');
    expect(execFileSync(process.execPath, ['--version']).toString()).toMatch(/^v24\./);
  });

  it('re-verifies the zero-knowledge proofs in the bare folder when given the bb program, and says "not verified" without it', async () => {
    await ready();
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'legx-onefile-zk-')));
    await bundleCli(join(dir, 'verify.js'));
    writeFileSync(join(dir, 'bundle.zip'), await withZk({}));
    const bb = join(
      import.meta.dirname,
      '../../../node_modules/.pnpm/@aztec+bb.js@5.0.0/node_modules/@aztec/bb.js/build',
      `${process.arch === 'arm64' ? 'arm64' : 'amd64'}-${process.platform === 'darwin' ? 'macos' : 'linux'}`,
      'bb',
    );
    const run = (extra: string[]) =>
      spawnSync(
        process.execPath,
        [
          join(dir, 'verify.js'),
          join(dir, 'bundle.zip'),
          '--out-dir',
          dir,
          '--profile',
          'demo',
          '--insecure-unpinned',
          '--insecure-bundle-tsa-roots',
          ...extra,
        ],
        { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH ?? '' } },
      );
    const without = run([]);
    expect(without.status).toBe(0);
    expect(without.stdout).toContain('pass --bb');
    expect(run(['--require-complete']).status).toBe(1);
    const withBb = run(['--bb', bb]);
    expect(withBb.stderr).not.toContain('Error');
    expect(withBb.status).toBe(0);
    const zk = JSON.parse(readFileSync(join(dir, 'legx-verify-report.json'), 'utf8')).findings.filter(
      (f: { check: string }) => f.check === 'zk-proof',
    );
    expect(zk.map((f: { status: string }) => f.status)).toEqual(['pass', 'pass']);
  });
});
