import { readFileSync } from 'node:fs';
import { SpanStatusCode } from '@opentelemetry/api';
import { afterEach, describe, expect, it } from 'vitest';
import { ALLOWED_ATTRIBUTES, BLOCKED_VALUES, scrubString } from '../src/allowlist.ts';
import { collectorConfig } from '../src/collector.ts';
import { captureSpans, type SpanCapture } from './helpers/capture.ts';

// Set by each test that captures spans; undefined for the tests that do not.
let cap = undefined as unknown as SpanCapture;
afterEach(() => cap?.shutdown());

describe('P3.6-05 an attribute not on the allow-list is dropped', () => {
  it('drops unlisted keys on spans, events and links; keeps listed ones; drops the status message', async () => {
    cap = captureSpans();
    const other = cap.tracer.startSpan('other');
    const span = cap.tracer.startSpan('anything', {
      attributes: {
        'deal.id': 'd1',
        'passport.name': 'ALICE',
        'user.email': 'a@b.example',
        'http.url': 'https://x/?q=1',
      },
      links: [{ context: other.spanContext(), attributes: { 'bar.number': '12345', 'deal.id': 'd1' } }],
    });
    span.setAttribute('http.route', '/deals/:id');
    span.setAttribute('mrz', 'secret');
    span.addEvent('step', { salt: 'ab'.repeat(32), 'gate.result': 'passed' });
    span.recordException(new Error('contains ALICE'));
    span.setStatus({ code: SpanStatusCode.ERROR, message: 'failed for ALICE' });
    span.end();
    other.end();
    const out = cap.exported().find((s) => s.name === 'anything');
    expect(out?.attributes).toEqual({ 'deal.id': 'd1', 'http.route': '/deals/:id' });
    expect(out?.links[0]?.attributes).toEqual({ 'deal.id': 'd1' });
    expect(out?.events.map((e) => e.attributes)).toEqual([{ 'gate.result': 'passed' }, {}]);
    expect(out?.status).toEqual({ code: SpanStatusCode.ERROR });
    expect(JSON.stringify(out?.events)).not.toContain('ALICE');
  });

  it('masks blocked values even under an allowed key', async () => {
    cap = captureSpans();
    const s = cap.tracer.startSpan('x', {
      attributes: {
        'gate.finding_code': 'P<UTOEXAMPLE<<ALICE<<<<<<<<<<<<<<<<<<<<<<<<<<<',
        'deal.state': 'a@b.example',
      },
    });
    s.end();
    expect(cap.exported()[0]?.attributes).toEqual({ 'gate.finding_code': '[REDACTED]', 'deal.state': '[REDACTED]' });
  });

  it('masks blocked values in the span name and in event names', async () => {
    cap = captureSpans();
    const s = cap.tracer.startSpan('GET alice@example.com');
    s.addEvent('sent to bob@example.com');
    s.end();
    expect(cap.exported()[0]?.name).toBe('GET [REDACTED]');
    expect(cap.exported()[0]?.events[0]?.name).toBe('sent to [REDACTED]');
  });
});

describe('blocked value patterns (DESIGN 8.6)', () => {
  const MRZ1 = 'P<UTOEXAMPLE<<ALICE<<<<<<<<<<<<<<<<<<<<<<<<<<<';
  const MRZ2 = 'XD00000012UTO9001014F3406301<<<<<<<<<<<<<<04';
  it.each([
    ['email', 'mail a.b+c@example.co.uk now'],
    ['family seed', 'seed sn5XhHuCYtU3NX9MCjrAMzZnYvvbT here'],
    ['MRZ line 1', MRZ1],
    ['MRZ line 2', MRZ2],
    ['hex of 64 bytes', `bytes ${'ab'.repeat(64)}`],
    ['base64 of 93 bytes', Buffer.alloc(93, 7).toString('base64')],
    ['PEM header', '-----BEGIN PRIVATE KEY-----'],
  ])('masks %s', (_n, text) => {
    expect(scrubString(text)).toContain('[REDACTED]');
  });

  it.each(['tesSUCCESS', 'deal 0192f7c2-8f3a-7c1e-9d4b-2a6e5f4c3b21', 'AB'.repeat(32), '/deals/:id'])(
    'leaves %s alone',
    (text) => {
      expect(scrubString(text)).toBe(text);
    },
  );

  it('masks every occurrence and is idempotent', () => {
    const once = scrubString(`${MRZ1} and ${MRZ1} and a@b.example`);
    expect(once.match(/\[REDACTED\]/g)).toHaveLength(3);
    expect(scrubString(once)).toBe(once);
  });
});

describe('Collector config', () => {
  const file = readFileSync(new URL('../collector/otel-collector.yaml', import.meta.url), 'utf8');

  it('the committed file equals what collectorConfig() renders', () => {
    expect(file).toBe(collectorConfig());
  });

  it('is fail-closed and lists exactly the allow-list', () => {
    expect(file).toContain('allow_all_keys: false');
    const keys = [...file.matchAll(/^ {6}- "([a-z_.]+)"$/gm)].map((m) => m[1]);
    expect(keys).toEqual([...ALLOWED_ATTRIBUTES]);
  });

  it('carries every blocked value pattern, each a valid regular expression', () => {
    for (const b of BLOCKED_VALUES) {
      expect(file).toContain(JSON.stringify(b.pattern));
      expect(() => new RegExp(b.pattern)).not.toThrow();
    }
  });

  it('uses the hashing function and summary mode of DESIGN 8.6', () => {
    expect(file).toContain('hash_function: hmac-sha256');
    // The Collector refuses to start without an HMAC key when hash_function is an HMAC (found by running the contrib image).
    expect(file).toContain(`hmac_key: "\${env:LEGX_REDACTION_HMAC_KEY}"`);
    expect(file).toContain('summary: info');
  });
});
