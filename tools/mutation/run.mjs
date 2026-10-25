// Runs StrykerJS for one target: a critical file name from targets.mjs, or `rest` (IMPLEMENTATION 5.4).
// Usage: node tools/mutation/run.mjs releaseGate
import { spawnSync } from 'node:child_process';

const target = process.argv[2];
if (!target) throw new Error('usage: node tools/mutation/run.mjs <file|rest>');
const r = spawnSync('pnpm', ['exec', 'stryker', 'run', ...process.argv.slice(3)], {
  stdio: 'inherit',
  env: { ...process.env, LEGX_TARGET: target },
});
process.exit(r.status ?? 1);
