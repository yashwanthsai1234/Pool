// Builds tests/system/REGRESSION.md: every issue ID of build/ISSUES.md mapped to the test that pins it.
// `node tests/system/support/regression.ts` rewrites the file; test/catalogue.test.ts checks it is complete and current.
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '../../..');
const sh = (c: string) => execSync(c, { cwd: ROOT, encoding: 'utf8', shell: '/bin/bash', maxBuffer: 1 << 26 });

export interface IssueRow {
  id: string;
  where: string;
  problem: string;
  state: string;
}

export function issueRows(): IssueRow[] {
  const rows: IssueRow[] = [];
  for (const line of readFileSync(join(ROOT, 'build/ISSUES.md'), 'utf8').split('\n')) {
    const cells = line.split('|').map((c) => c.trim());
    const id = cells[1];
    if (id && /^I-[A-Za-z0-9][A-Za-z0-9.-]*$/.test(id) && cells.length >= 7)
      rows.push({ id, where: cells[3] ?? '', problem: cells[4] ?? '', state: cells[6] ?? '' });
  }
  return rows;
}

/** Test files that name an issue, by tier. The system tests name an ID inside their title or a comment. */
export function pins(id: string): { system: string[]; package: string[] } {
  const re = `(^|[^A-Za-z0-9.\\-])${id.replace(/\./g, '\\.')}([^A-Za-z0-9.\\-]|$)`;
  const files = sh(
    `grep -rlE "${re}" tests/system/test packages/*/test packages/*/test-int services/*/test services/*/test-int apps/*/test apps/*/test-int tools/*/test spec/test 2>/dev/null || true`,
  )
    .trim()
    .split('\n')
    .filter(Boolean);
  return {
    system: files.filter((f) => f.startsWith('tests/system/')),
    package: files.filter((f) => !f.startsWith('tests/system/')),
  };
}

const short = (s: string, n = 110) =>
  s.length > n ? `${s.slice(0, n - 3).replace(/\|/g, '/')}...` : s.replace(/\|/g, '/');

export function render(): string {
  const rows = issueRows();
  const lines = [
    '# Regression catalogue (Phase 6)',
    '',
    'Every issue of `build/ISSUES.md` and the test that pins it. Regenerate with `node tests/system/support/regression.ts`;',
    '`tests/system/test/catalogue.test.ts` fails when an issue is missing here or a test names an issue that does not exist.',
    '',
    '- **system**: a `tests/system` test names the issue. An `it.fails(...)` there is a known gap that flips to a failure the day the issue is fixed (change it to `it`).',
    '- **package**: a unit or integration test of the owning package names the issue (an `it.todo`, `KNOWN GAP` or a regression test).',
    '- **none**: no test names the issue yet. Most are design, documentation or process items; the code ones are listed under "Pin needed" below.',
    '',
    '| Issue | Where | System test | Package tests | Tier |',
    '|---|---|---|---|---|',
  ];
  const unpinned: IssueRow[] = [];
  for (const r of rows) {
    const p = pins(r.id);
    const tier = p.system.length ? 'system' : p.package.length ? 'package' : 'none';
    if (tier === 'none') unpinned.push(r);
    lines.push(
      `| ${r.id} | ${short(r.where, 50)} | ${p.system.map((f) => `\`${f.replace('tests/system/test/', '')}\``).join(', ') || '-'} | ${
        p.package
          .slice(0, 3)
          .map((f) => `\`${f}\``)
          .join(', ') || '-'
      }${p.package.length > 3 ? ` (+${p.package.length - 3})` : ''} | ${tier} |`,
    );
  }
  lines.push(
    '',
    '## Pin needed',
    '',
    'Issues with no test that names them. Whoever fixes the issue adds the test and names the ID in it.',
    '',
  );
  for (const r of unpinned) lines.push(`- ${r.id}: ${short(r.problem, 140)} (${r.state || 'open'})`);
  lines.push(
    '',
    '## SYS-* index',
    '',
    'Test IDs of IMPLEMENTATION 6.1 to 6.4 and the file that holds them (`tests/system/test/`):',
    '',
  );
  const sys = sh('grep -ohE "SYS-([0-9]{2}|[AIR][0-9]+)[a-z]?" tests/system/test/*.ts | sort -uV').trim().split('\n');
  lines.push(sys.join(', '), '');
  return lines.join('\n');
}

if (import.meta.main) writeFileSync(join(ROOT, 'tests/system/REGRESSION.md'), render());
