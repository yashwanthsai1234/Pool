// Runs `tsc -p` on the root and on every package's own tsconfig.json (IMPLEMENTATION 4.2).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const roots = ['packages', 'services', 'apps', 'tools'];
const projects = [
  'tsconfig.json',
  ...roots.flatMap((r) =>
    existsSync(r)
      ? readdirSync(r)
          .map((d) => join(r, d, 'tsconfig.json'))
          .filter(existsSync)
      : [],
  ),
];
let failed = 0;
for (const p of projects) {
  try {
    execFileSync('tsc', ['-p', p], { stdio: 'inherit' });
    console.log(`ok  ${p}`);
  } catch {
    failed++;
    console.error(`FAIL ${p}`);
  }
}
process.exit(failed ? 1 : 0);
