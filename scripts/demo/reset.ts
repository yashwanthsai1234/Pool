// `node scripts/demo/reset.ts [--keep-testnet]`: stops the local stack, wipes the local ledger and Postgres containers
// and removes demo/state.json (and demo/dry-run.json), so the next seed starts clean. Testnet accounts cannot be
// refunded by reset: --keep-testnet keeps state.json when it is a Testnet one (the funded accounts are reused).
// Source: https://docs.docker.com/reference/cli/docker/container/rm/

import { spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROOT, readState, resetState } from './lib.ts';

spawnSync('node', [resolve(ROOT, 'scripts/dev.ts'), '--down'], { stdio: 'inherit' });
const keep = process.argv.includes('--keep-testnet') && readState()?.network === 'testnet';
if (!keep) resetState();
rmSync(resolve(ROOT, 'demo', 'dry-run.json'), { force: true });
process.stdout.write(keep ? 'stack removed; Testnet state kept\n' : 'stack removed; demo/state.json removed\n');
