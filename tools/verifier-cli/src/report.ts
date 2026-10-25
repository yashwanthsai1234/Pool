// The report model: every check yields findings; the exit code is 1 if any finding failed. A finding names the file and
// the check, so an arbitrator can point at exactly what is wrong (IMPLEMENTATION P3.8-02).
export type Status = 'pass' | 'fail' | 'warn' | 'skip';

export interface Finding {
  readonly check: string;
  readonly file: string;
  readonly status: Status;
  readonly message: string;
}

export class Findings {
  readonly list: Finding[] = [];
  add(check: string, file: string, status: Status, message: string): undefined {
    this.list.push({ check, file, status, message });
  }
  pass(check: string, file: string, message: string): undefined {
    this.add(check, file, 'pass', message);
  }
  fail(check: string, file: string, message: string): undefined {
    this.add(check, file, 'fail', message);
  }
  warn(check: string, file: string, message: string): undefined {
    this.add(check, file, 'warn', message);
  }
  skip(check: string, file: string, message: string): undefined {
    this.add(check, file, 'skip', message);
  }
}

export interface Report {
  readonly tool: 'legx-verify';
  readonly bundle: { readonly name: string; readonly sha256: string; readonly dealId: string | undefined };
  readonly profile: 'production' | 'demo';
  readonly result: 'pass' | 'fail';
  readonly summary: Readonly<Record<string, { pass: number; fail: number; warn: number; skip: number }>>;
  readonly findings: readonly Finding[];
}

export function buildReport(
  bundle: Report['bundle'],
  profile: Report['profile'],
  findings: readonly Finding[],
): Report {
  const summary: Record<string, { pass: number; fail: number; warn: number; skip: number }> = {};
  for (const f of findings) {
    const s = summary[f.check] ?? { pass: 0, fail: 0, warn: 0, skip: 0 };
    s[f.status]++;
    summary[f.check] = s;
  }
  const result = findings.some((f) => f.status === 'fail') ? 'fail' : 'pass';
  return { tool: 'legx-verify', bundle, profile, result, summary, findings };
}

const LABEL: Record<Status, string> = { pass: 'PASS', fail: 'FAIL', warn: 'WARN', skip: 'SKIP' };

/** A plain text report: one line per check with its counts, then every failure, warning and skip by file. */
export function renderText(r: Report): string {
  const lines = [
    'LEGX EVIDENCE BUNDLE VERIFICATION',
    `bundle:  ${r.bundle.name}`,
    `sha256:  ${r.bundle.sha256}`,
    `deal:    ${r.bundle.dealId ?? '(unknown)'}`,
    `profile: ${r.profile}`,
    '',
    'Checks',
  ];
  for (const [check, c] of Object.entries(r.summary)) {
    const status = c.fail > 0 ? 'FAIL' : c.pass > 0 ? 'PASS' : c.warn > 0 ? 'WARN' : 'SKIP';
    lines.push(
      `  ${status}  ${check}  (${c.pass} passed, ${c.fail} failed, ${c.warn} warnings, ${c.skip} not verified)`,
    );
  }
  const notable = r.findings.filter((f) => f.status !== 'pass');
  if (notable.length > 0) {
    lines.push('', 'Details');
    for (const f of notable) lines.push(`  ${LABEL[f.status]}  ${f.file}  [${f.check}]  ${f.message}`);
  }
  lines.push('', `RESULT: ${r.result === 'pass' ? 'PASS' : 'FAIL'}`);
  return `${lines.join('\n')}\n`;
}
