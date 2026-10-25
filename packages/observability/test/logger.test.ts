import { Writable } from 'node:stream';
import { SCHEMAS } from '@legx/contracts/catalog';
import { secretPaths } from '@legx/contracts/secret';
import { describe, expect, it } from 'vitest';
import { contractSecretPaths, createLogger, redactPaths, scrubDeep, secretKeyNames } from '../src/logger.ts';
import { withLegxSpan } from '../src/spans.ts';
import { captureSpans } from './helpers/capture.ts';

const lines: string[] = [];
const sink = () => {
  lines.length = 0;
  return new Writable({
    write(chunk, _enc, cb) {
      lines.push(String(chunk));
      cb();
    },
  });
};

describe('redact paths come from the contracts', () => {
  it('cover every Secret<> field of every schema (nothing is added by hand for contract fields)', () => {
    const fromSchemas = new Set(Object.values(SCHEMAS).flatMap((s) => secretPaths(s)));
    expect(fromSchemas.size).toBeGreaterThan(0);
    expect([...fromSchemas].sort()).toEqual(contractSecretPaths());
    const keys = secretKeyNames();
    for (const p of fromSchemas) expect(keys.has((p.split('/').at(-1) ?? '').toLowerCase())).toBe(true);
  });

  it('are valid pino paths (the logger starts) and include known fields at the top and one level down', () => {
    const paths = redactPaths();
    for (const f of [
      'barNumber',
      '*.barNumber',
      'barSalt',
      'firstname',
      'request.queryResult',
      '*.request.queryResult',
    ]) {
      expect(paths).toContain(f);
    }
    expect(() => createLogger({ destination: sink() })).not.toThrow();
  });
});

describe('logger', () => {
  it.each([
    ['top level', { barNumber: 'CA-123456' }],
    ['one level down', { body: { barNumber: 'CA-123456' } }],
    ['five levels down', { a: { b: { c: { d: { barNumber: 'CA-123456' } } } } }],
    ['inside an array', { rows: [{ barNumber: 'CA-123456' }] }],
    ['upper case key', { BARNUMBER: 'CA-123456' }],
  ])('masks a contract secret %s', (_n, obj) => {
    createLogger({ destination: sink() }).info(obj, 'step');
    expect(lines.join('')).not.toContain('CA-123456');
    expect(lines.join('')).toContain('[REDACTED]');
  });

  it('masks every disclosed fact from DisclosedFacts', () => {
    createLogger({ destination: sink() }).info({
      facts: { firstname: 'ALICE', lastname: 'EXAMPLE', birthdate: '1990-01-01', nationality: 'UTO' },
    });
    for (const v of ['ALICE', 'EXAMPLE', '1990-01-01', 'UTO']) expect(lines.join('')).not.toContain(v);
  });

  it('never prints byte arrays or buffers, only their length', () => {
    createLogger({ destination: sink() }).info({
      whatever: new Uint8Array([1, 2, 3, 4, 5]),
      buf: Buffer.from('xyz'),
      nested: { b: new Uint8Array(93) },
    });
    const out = lines.join('');
    expect(out).toContain('[5 bytes]');
    expect(out).toContain('[93 bytes]');
    expect(out).not.toMatch(/"0":1/);
  });

  it('scrubs the message, printf arguments and error text', () => {
    const log = createLogger({ destination: sink() });
    const mrz = 'P<UTOEXAMPLE<<ALICE<<<<<<<<<<<<<<<<<<<<<<<<<<<';
    log.info(`read ${mrz}`);
    log.info({ err: new Error(`bad ${mrz}`) }, 'failed');
    log.error({ error: new Error(`bad ${mrz}`) });
    log.info('%s', mrz);
    expect(lines.join('')).not.toContain('P<UTO');
  });

  it('joins logs to traces: trace_id and span_id of the active span', async () => {
    const cap = captureSpans();
    const log = createLogger({ destination: sink() });
    await withLegxSpan(cap.tracer, 'legx.ops.bind', {}, () => log.info('inside'));
    log.info('outside');
    const [inside, outside] = lines.map((l) => JSON.parse(l));
    expect(inside.trace_id).toBe(cap.exported()[0]?.spanContext().traceId);
    expect(inside.span_id).toBe(cap.exported()[0]?.spanContext().spanId);
    expect(outside.trace_id).toBeUndefined();
    await cap.shutdown();
  });

  it('stays bounded on cycles and deep objects', () => {
    const a: Record<string, unknown> = {};
    a.self = a;
    const out = JSON.stringify(scrubDeep(a, new Set()));
    expect(out).toContain('[too deep]');
    expect(() => createLogger({ destination: sink() }).info(a)).not.toThrow();
  });

  it('keeps ordinary fields', () => {
    createLogger({ destination: sink() }).info({ 'deal.id': 'd1', state: 'FUNDED', n: 3 }, 'ok');
    const rec = JSON.parse(lines[0] ?? '{}');
    expect(rec).toMatchObject({ 'deal.id': 'd1', state: 'FUNDED', n: 3, msg: 'ok' });
  });
});
