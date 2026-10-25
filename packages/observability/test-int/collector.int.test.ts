// P3.6-05 against the real Collector: an attribute that is not on the allow-list is dropped, and blocked values are
// masked, by the redaction processor of the config we ship (rendered by collectorConfig()).
// Image: otel/opentelemetry-collector-contrib (the redaction processor is a contrib component).
// Source: https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { collectorConfig } from '../src/collector.ts';

const NAME = 'legx-3.6-otelcol';
const PORT = 9101;
const IMAGE = 'otel/opentelemetry-collector-contrib:latest';
const docker = (...args: string[]) => execFileSync('docker', args, { stdio: 'pipe' }).toString();
/** Container logs go to stderr, so read both streams. */
const logs = () => {
  const r = spawnSync('docker', ['logs', NAME], { encoding: 'utf8' });
  return r.stdout + r.stderr;
};
const dir = join(tmpdir(), `legx-otelcol-${process.pid}`);
const OUT = '/out/traces.json';

const str = (key: string, value: string) => ({ key, value: { stringValue: value } });

beforeAll(async () => {
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777);
  writeFileSync(join(dir, 'config.yaml'), collectorConfig({ fileExporterPath: OUT }));
  try {
    docker('rm', '-f', NAME);
  } catch {
    // no earlier container
  }
  docker(
    'run',
    '-d',
    '--name',
    NAME,
    '-e',
    'LEGX_REDACTION_HMAC_KEY=test-only-key-0123456789abcdef0123456789abcdef',
    '-p',
    `${PORT}:4318`,
    '-v',
    `${join(dir, 'config.yaml')}:/etc/otelcol/config.yaml:ro`,
    '-v',
    `${dir}:/out`,
    IMAGE,
    '--config=/etc/otelcol/config.yaml',
  );
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      if (r.status < 500) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Collector did not start:\n${logs()}`);
}, 120_000);

afterAll(() => {
  docker('rm', '-f', NAME);
  rmSync(dir, { recursive: true, force: true });
});

describe('P3.6-05 the Collector redaction processor', () => {
  it('drops attributes that are not on the allow-list and masks blocked values', async () => {
    const now = BigInt(Date.now()) * 1_000_000n;
    const body = {
      resourceSpans: [
        {
          resource: { attributes: [] },
          scopeSpans: [
            {
              scope: { name: 'test' },
              spans: [
                {
                  traceId: 'a'.repeat(32),
                  spanId: 'b'.repeat(16),
                  name: 'legx.release.gate',
                  kind: 1,
                  startTimeUnixNano: String(now),
                  endTimeUnixNano: String(now + 1000n),
                  attributes: [
                    str('deal.id', 'deal-123'),
                    str('gate.result', 'passed'),
                    str('passport.name', 'ALICE EXAMPLE'),
                    str('user.email', 'alice@example.com'),
                    str('gate.finding_code', 'P<UTOEXAMPLE<<ALICE<<<<<<<<<<<<<<<<<<<<<<<<<<<'),
                  ],
                },
              ],
            },
          ],
        },
      ],
    };
    const res = await fetch(`http://127.0.0.1:${PORT}/v1/traces`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(200);
    let text = '';
    for (let i = 0; i < 40 && !text; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const file = join(dir, 'traces.json');
      text = existsSync(file) ? readFileSync(file, 'utf8') : '';
    }
    expect(text, logs()).not.toBe('');
    const attrs = JSON.parse(text.split('\n')[0] ?? '{}').resourceSpans[0].scopeSpans[0].spans[0].attributes as {
      key: string;
      value: { stringValue: string };
    }[];
    const byKey = Object.fromEntries(attrs.map((a) => [a.key, a.value.stringValue]));
    expect(byKey['deal.id']).toBe('deal-123');
    expect(byKey['gate.result']).toBe('passed');
    expect(byKey['passport.name']).toBeUndefined();
    expect(byKey['user.email']).toBeUndefined();
    expect(text).not.toContain('ALICE');
    expect(text).not.toContain('alice@example.com');
    expect(byKey['gate.finding_code']).not.toContain('P<UTO');
  });
});
