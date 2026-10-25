import { type Attributes, context, type Tracer } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { InMemorySpanExporter, type ReadableSpan, SimpleSpanProcessor, TracerProvider } from '@opentelemetry/sdk-trace';
import { AllowListSpanExporter } from '../../src/exporter.ts';

export interface SpanCapture {
  readonly tracer: Tracer;
  readonly exported: () => ReadableSpan[];
  shutdown(): Promise<void>;
}

/** A tracer whose spans reach an in-memory exporter only through the allow-list exporter, like production. */
// NodeSDK installs this context manager in production; a bare provider needs it for nested spans.
context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());

export function captureSpans(): SpanCapture {
  const memory = new InMemorySpanExporter();
  const provider = new TracerProvider({
    spanProcessors: [new SimpleSpanProcessor({ exporter: new AllowListSpanExporter(memory) })],
  });
  return {
    tracer: provider.getTracer('test'),
    exported: () => memory.getFinishedSpans(),
    shutdown: () => provider.shutdown(),
  };
}

/** Everything an exporter could serialize from a span, as one searchable string. */
export const spanText = (s: ReadableSpan): string =>
  JSON.stringify({
    name: s.name,
    attributes: s.attributes,
    status: s.status,
    events: s.events.map((e) => ({ name: e.name, attributes: e.attributes })),
    links: s.links.map((l) => l.attributes),
    resource: s.resource.attributes as Attributes,
  });
