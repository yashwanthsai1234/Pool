import { SpanStatusCode, trace } from '@opentelemetry/api';
import { afterEach, describe, expect, it } from 'vitest';
import { ALLOWED_ATTRIBUTES } from '../src/allowlist.ts';
import { type LegxSpanName, SPAN_ATTRIBUTES, withLegxSpan } from '../src/spans.ts';
import { captureSpans, type SpanCapture } from './helpers/capture.ts';

// Set by each test that captures spans; undefined for the tests that do not.
let cap = undefined as unknown as SpanCapture;
afterEach(() => cap?.shutdown());

const DEAL = '0192f7c2-8f3a-7c1e-9d4b-2a6e5f4c3b21';
const SAMPLE: Record<string, string | number> = {
  'deal.id': DEAL,
  'deal.phase': 'lock',
  'bar.result': 'active',
  'bar.source_kind': 'registry',
  'xrpl.tx_hash': 'AB'.repeat(32),
  'xrpl.engine_result': 'tesSUCCESS',
  'xrpl.ledger_index': 1234,
  'credential.result': 'issued',
  'attest.side': 'A',
  'attest.result': 'pass',
  'attest.chip_auth': 'aa',
  'gate.result': 'passed',
  'gate.finding_code': 'NONE',
};

describe('P3.6-04 one span per new step, with deal.id and the trace ID', () => {
  it('has exactly the nine spans of DESIGN 8.6 and every attribute is on the allow-list', () => {
    expect(Object.keys(SPAN_ATTRIBUTES).sort()).toEqual(
      [
        'legx.contract.lawyer_sign',
        'legx.ops.bind',
        'legx.bar.verify',
        'legx.bar.deal_link',
        'legx.credential.issue',
        'legx.nft.mint',
        'legx.passport.check',
        'legx.release.gate',
        'legx.release.perform',
      ].sort(),
    );
    for (const attrs of Object.values(SPAN_ATTRIBUTES)) for (const a of attrs) expect(ALLOWED_ATTRIBUTES).toContain(a);
  });

  it.each(Object.entries(SPAN_ATTRIBUTES))(
    '%s: the in-memory exporter sees it with its attributes and a trace ID',
    async (name, keys) => {
      cap = captureSpans();
      const attrs = Object.fromEntries(keys.map((k) => [k, SAMPLE[k] as string | number]));
      await withLegxSpan(cap.tracer, name as LegxSpanName, attrs, () => undefined);
      const spans = cap.exported();
      expect(spans).toHaveLength(1);
      expect(spans[0]?.name).toBe(name);
      expect(spans[0]?.attributes).toEqual(attrs);
      expect(spans[0]?.spanContext().traceId).toMatch(/^[0-9a-f]{32}$/);
      if ((keys as readonly string[]).includes('deal.id')) expect(spans[0]?.attributes['deal.id']).toBe(DEAL);
    },
  );

  it('nested steps share one trace', async () => {
    cap = captureSpans();
    await withLegxSpan(cap.tracer, 'legx.release.gate', { 'deal.id': DEAL }, () =>
      withLegxSpan(
        cap.tracer,
        'legx.release.perform',
        { 'deal.id': DEAL },
        () => trace.getActiveSpan()?.spanContext().traceId,
      ),
    );
    const [inner, outer] = cap.exported();
    expect(inner?.spanContext().traceId).toBe(outer?.spanContext().traceId);
    expect(inner?.parentSpanContext?.spanId).toBe(outer?.spanContext().spanId);
  });

  it('refuses unknown names and attributes the table does not list for that span', async () => {
    cap = captureSpans();
    await expect(withLegxSpan(cap.tracer, 'legx.nope' as LegxSpanName, {}, () => 1)).rejects.toThrow(/unknown span/);
    await expect(withLegxSpan(cap.tracer, 'toString' as LegxSpanName, {}, () => 1)).rejects.toThrow(/unknown span/);
    await expect(withLegxSpan(cap.tracer, 'legx.bar.verify', { 'deal.id': DEAL } as never, () => 1)).rejects.toThrow(
      /not allowed/,
    );
    await expect(
      withLegxSpan(cap.tracer, 'legx.bar.verify', { 'passport.name': 'x' } as never, () => 1),
    ).rejects.toThrow(/not allowed/);
    await expect(
      withLegxSpan(cap.tracer, 'legx.bar.verify', { 'bar.result': { a: 1 } } as never, () => 1),
    ).rejects.toThrow(/primitive/);
    expect(cap.exported()).toHaveLength(0);
  });

  it('a failing step ends its span with an error status and no message or exception event', async () => {
    cap = captureSpans();
    await expect(
      withLegxSpan(cap.tracer, 'legx.passport.check', { 'deal.id': DEAL }, () => {
        throw new Error('bad MRZ P<UTOEXAMPLE<<ALICE<<<<<<<<<<<<<<<<<<<<<<<<<<<');
      }),
    ).rejects.toThrow(/bad MRZ/);
    const s = cap.exported()[0];
    expect(s?.status).toEqual({ code: SpanStatusCode.ERROR });
    expect(s?.events).toHaveLength(0);
  });

  it('returns the result of the step and awaits async steps', async () => {
    cap = captureSpans();
    expect(await withLegxSpan(cap.tracer, 'legx.ops.bind', {}, async () => 42)).toBe(42);
    expect(cap.exported()[0]?.ended).toBe(true);
  });
});
