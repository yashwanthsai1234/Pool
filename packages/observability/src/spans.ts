// The spans of DESIGN 8.6 ("Spans for the new steps") and a helper that makes each one: the name must be in the table,
// the attributes must be the ones the table lists for it, and a failure records only a status, never the error message
// (messages can carry user data). The trace ID comes from the active trace context; `deal.id` is set on purpose.
// Source: DESIGN 8.6; https://opentelemetry.io/docs/specs/otel/trace/exceptions/ (we deliberately skip recordException)
import { type Attributes, type Span, SpanStatusCode, type Tracer } from '@opentelemetry/api';
import { type AllowedAttribute, isAllowedAttribute, scrubString } from './allowlist.ts';

export const SPAN_ATTRIBUTES = {
  'legx.contract.lawyer_sign': ['deal.id', 'deal.phase'],
  'legx.ops.bind': ['deal.id', 'deal.phase'],
  'legx.bar.verify': ['bar.result', 'bar.source_kind'],
  'legx.bar.deal_link': ['deal.id', 'bar.result'],
  'legx.credential.issue': ['xrpl.tx_hash', 'xrpl.engine_result', 'credential.result'],
  'legx.nft.mint': ['deal.id', 'xrpl.tx_hash', 'xrpl.engine_result'],
  'legx.passport.check': ['deal.id', 'attest.side', 'attest.result', 'attest.chip_auth'],
  'legx.release.gate': ['deal.id', 'gate.result', 'gate.finding_code'],
  'legx.release.perform': ['deal.id', 'xrpl.tx_hash', 'xrpl.ledger_index', 'xrpl.engine_result'],
} as const satisfies Record<string, readonly AllowedAttribute[]>;
export type LegxSpanName = keyof typeof SPAN_ATTRIBUTES;
type AttrKey<N extends LegxSpanName> = (typeof SPAN_ATTRIBUTES)[N][number];

/** Attribute values for span `N`: only its own keys, primitives only. */
export type SpanAttrs<N extends LegxSpanName> = { [K in AttrKey<N>]?: string | number | boolean };

/** Runs `fn` inside the span `name`. Throws a programmer error for an unknown name or a key the table does not list. */
export async function withLegxSpan<N extends LegxSpanName, T>(
  tracer: Tracer,
  name: N,
  attributes: SpanAttrs<N>,
  fn: (span: Span) => Promise<T> | T,
): Promise<T> {
  const listed: readonly string[] | undefined = Object.hasOwn(SPAN_ATTRIBUTES, name)
    ? SPAN_ATTRIBUTES[name]
    : undefined;
  if (!listed) throw new Error(`unknown span name: ${String(name)}`);
  const clean: Attributes = {};
  for (const [k, v] of Object.entries(attributes)) {
    if (!listed.includes(k) || !isAllowedAttribute(k)) throw new Error(`attribute ${k} is not allowed on span ${name}`);
    if (v === undefined) continue;
    if (!['string', 'number', 'boolean'].includes(typeof v)) throw new Error(`attribute ${k} must be a primitive`);
    clean[k] = typeof v === 'string' ? scrubString(v) : (v as number | boolean);
  }
  return tracer.startActiveSpan(name, { attributes: clean }, async (span) => {
    try {
      return await fn(span);
    } catch (e) {
      span.setStatus({ code: SpanStatusCode.ERROR }); // no message, no exception event
      throw e;
    } finally {
      span.end();
    }
  });
}
