// The in-process half of the fail-closed redaction (the Collector is the second half, `collector.ts`): a SpanExporter
// wrapper that hands the inner exporter a copy of each span with only allow-listed attributes, scrubbed values, no event
// or link attributes that are off the list, and no status message. Nothing reaches an exporter without passing here.
// Source: https://opentelemetry.io/docs/specs/otel/trace/sdk/#span-exporter

import type { Attributes, AttributeValue } from '@opentelemetry/api';
import type { ExportResult } from '@opentelemetry/core';
import type { ReadableSpan, SpanExporter } from '@opentelemetry/sdk-trace';
import { isAllowedAttribute, scrubString } from './allowlist.ts';

const scrubValue = (v: AttributeValue): AttributeValue =>
  typeof v === 'string'
    ? scrubString(v)
    : Array.isArray(v)
      ? (v.map((x) => (typeof x === 'string' ? scrubString(x) : x)) as AttributeValue)
      : v;

function filterAttributes(attrs: Attributes): Attributes {
  const out: Attributes = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && isAllowedAttribute(k)) out[k] = scrubValue(v);
  }
  return out;
}

function filterSpan(span: ReadableSpan): ReadableSpan {
  return {
    name: scrubString(span.name),
    kind: span.kind,
    spanContext: () => span.spanContext(),
    parentSpanContext: span.parentSpanContext,
    startTime: span.startTime,
    endTime: span.endTime,
    status: { code: span.status.code },
    attributes: filterAttributes(span.attributes),
    links: span.links.map((l) => ({ context: l.context, attributes: filterAttributes(l.attributes ?? {}) })),
    events: span.events.map((e) => ({
      name: scrubString(e.name),
      time: e.time,
      attributes: filterAttributes(e.attributes ?? {}),
    })),
    duration: span.duration,
    ended: span.ended,
    resource: span.resource,
    instrumentationScope: span.instrumentationScope,
    droppedAttributesCount: span.droppedAttributesCount,
    droppedEventsCount: span.droppedEventsCount,
    droppedLinksCount: span.droppedLinksCount,
  };
}

export class AllowListSpanExporter implements SpanExporter {
  readonly #inner: SpanExporter;
  constructor(inner: SpanExporter) {
    this.#inner = inner;
  }
  export(spans: ReadableSpan[], done: (result: ExportResult) => void): void {
    this.#inner.export(spans.map(filterSpan), done);
  }
  shutdown(): Promise<void> {
    return this.#inner.shutdown();
  }
  forceFlush(): Promise<void> {
    return this.#inner.forceFlush?.() ?? Promise.resolve();
  }
}
